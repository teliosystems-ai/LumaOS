"""Immutable artifact versions and append-only effect receipts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any
import uuid

from .db import LumaStore, utc_now
from .errors import ConflictError, NotFoundError, ValidationError


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ReceiptService:
    def __init__(self, store: LumaStore) -> None:
        self.store = store

    def find(self, owner: str, idempotency_key: str) -> dict[str, Any] | None:
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM effect_receipts WHERE owner=? AND idempotency_key=?",
                (owner, idempotency_key),
            ).fetchone()
        return self._row(row) if row is not None else None

    def record(
        self,
        owner: str,
        *,
        idempotency_key: str,
        effect_type: str,
        target: str,
        status: str,
        result: dict[str, Any],
        workflow_id: str | None = None,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        """Append one receipt, returning the previous one on exact replay."""

        with self.store.transaction(write=True) as connection:
            return self.record_in_transaction(
                connection,
                owner,
                idempotency_key=idempotency_key,
                effect_type=effect_type,
                target=target,
                status=status,
                result=result,
                workflow_id=workflow_id,
                step_id=step_id,
            )

    def record_in_transaction(
        self,
        connection: sqlite3.Connection,
        owner: str,
        *,
        idempotency_key: str,
        effect_type: str,
        target: str,
        status: str,
        result: dict[str, Any],
        workflow_id: str | None = None,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a receipt on a caller-owned transaction.

        This variant lets a domain state transition and its effect receipt
        commit or roll back together. Callers must already hold a write
        transaction for ``self.store``.
        """

        existing = connection.execute(
            "SELECT * FROM effect_receipts WHERE owner=? AND idempotency_key=?",
            (owner, idempotency_key),
        ).fetchone()
        if existing is not None:
            previous = self._row(existing)
            signature = (effect_type, target, status, _canonical_json(result), workflow_id, step_id)
            previous_signature = (
                previous["effect_type"], previous["target"], previous["status"],
                _canonical_json(previous["result"]), previous["workflow_id"], previous["step_id"],
            )
            if signature != previous_signature:
                raise ConflictError("Idempotency key was already used for a different effect")
            return previous
        receipt_id = str(uuid.uuid4())
        connection.execute(
            "INSERT INTO effect_receipts(receipt_id,owner,workflow_id,step_id,idempotency_key,effect_type,target,status,result_json,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id, owner, workflow_id, step_id, idempotency_key,
                effect_type, target, status, _canonical_json(result), utc_now(),
            ),
        )
        row = connection.execute("SELECT * FROM effect_receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        return self._row(row)

    def list(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM effect_receipts WHERE owner=? ORDER BY sequence DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row: object) -> dict[str, Any]:
        return {
            "sequence": int(row["sequence"]),  # type: ignore[index]
            "receipt_id": row["receipt_id"],  # type: ignore[index]
            "id": row["receipt_id"],  # type: ignore[index]
            "owner": row["owner"],  # type: ignore[index]
            "workflow_id": row["workflow_id"],  # type: ignore[index]
            "step_id": row["step_id"],  # type: ignore[index]
            "idempotency_key": row["idempotency_key"],  # type: ignore[index]
            "effect_type": row["effect_type"],  # type: ignore[index]
            "target": row["target"],  # type: ignore[index]
            "status": row["status"],  # type: ignore[index]
            "result": json.loads(row["result_json"]),  # type: ignore[index]
            "created_at": row["created_at"],  # type: ignore[index]
        }


class ArtifactService:
    def __init__(self, store: LumaStore, objects_dir: str | Path, receipts: ReceiptService | None = None) -> None:
        self.store = store
        self.objects_dir = Path(objects_dir)
        self.objects_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.receipts = receipts or ReceiptService(store)

    def create_text(
        self,
        owner: str,
        content: str,
        *,
        filename: str,
        media_type: str = "text/plain; charset=utf-8",
        provenance: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        workflow_id: str | None = None,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        return self.create_bytes(
            owner,
            content.encode("utf-8"),
            filename=filename,
            media_type=media_type,
            provenance=provenance,
            idempotency_key=idempotency_key,
            workflow_id=workflow_id,
            step_id=step_id,
        )

    def create_bytes(
        self,
        owner: str,
        content: bytes,
        *,
        filename: str,
        media_type: str,
        provenance: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        workflow_id: str | None = None,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        self._validate_metadata(owner, filename, media_type)
        if idempotency_key:
            receipt = self.receipts.find(owner, idempotency_key)
            if receipt is not None:
                result = receipt["result"]
                expected_hash = hashlib.sha256(content).hexdigest()
                if result.get("content_hash") != expected_hash or result.get("filename") != filename:
                    raise ConflictError("Idempotency key was already used for different artifact content")
                return self.get(owner, str(result["artifact_id"]), version=int(result["version"]))

        content_hash, storage_path = self._store_blob(content)
        now = utc_now()
        artifact_id = str(uuid.uuid4())
        receipt_id = str(uuid.uuid4())
        effect_key = idempotency_key or f"artifact:create:{artifact_id}"
        result = {
            "artifact_id": artifact_id,
            "version": 1,
            "filename": filename,
            "content_hash": content_hash,
            "size_bytes": len(content),
        }
        with self.store.transaction(write=True) as connection:
            if idempotency_key:
                existing = connection.execute(
                    "SELECT result_json FROM effect_receipts WHERE owner=? AND idempotency_key=?",
                    (owner, idempotency_key),
                ).fetchone()
                if existing is not None:
                    previous = json.loads(existing["result_json"])
                    if previous.get("content_hash") != content_hash or previous.get("filename") != filename:
                        raise ConflictError("Idempotency key was already used for different artifact content")
                    artifact_id = previous["artifact_id"]
                    # The concurrent winner is committed when our BEGIN IMMEDIATE starts.
                    return self._get_with_connection(connection, owner, artifact_id, int(previous["version"]))
            connection.execute(
                "INSERT INTO artifacts(artifact_id,owner,filename,media_type,current_version,created_at,updated_at) "
                "VALUES (?,?,?,?,1,?,?)",
                (artifact_id, owner, filename, media_type, now, now),
            )
            connection.execute(
                "INSERT INTO artifact_versions(artifact_id,version,content_hash,size_bytes,storage_path,provenance_json,created_at) "
                "VALUES (?,1,?,?,?,?,?)",
                (artifact_id, content_hash, len(content), storage_path, _canonical_json(provenance or {}), now),
            )
            connection.execute(
                "INSERT INTO effect_receipts(receipt_id,owner,workflow_id,step_id,idempotency_key,effect_type,target,status,result_json,created_at) "
                "VALUES (?,?,?,?,?,'artifact.commit',?,'SUCCEEDED',?,?)",
                (
                    receipt_id, owner, workflow_id, step_id, effect_key,
                    f"artifact:{artifact_id}:1", _canonical_json(result), now,
                ),
            )
        return self.get(owner, artifact_id, version=1)

    def add_version(
        self,
        owner: str,
        artifact_id: str,
        content: bytes,
        *,
        expected_current_version: int,
        provenance: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        workflow_id: str | None = None,
        step_id: str | None = None,
    ) -> dict[str, Any]:
        content_hash, storage_path = self._store_blob(content)
        if idempotency_key:
            receipt = self.receipts.find(owner, idempotency_key)
            if receipt is not None:
                result = receipt["result"]
                if result.get("artifact_id") != artifact_id or result.get("content_hash") != content_hash:
                    raise ConflictError("Idempotency key was already used for a different artifact version")
                return self.get(owner, artifact_id, version=int(result["version"]))
        now = utc_now()
        with self.store.transaction(write=True) as connection:
            if idempotency_key:
                existing = connection.execute(
                    "SELECT result_json FROM effect_receipts WHERE owner=? AND idempotency_key=?",
                    (owner, idempotency_key),
                ).fetchone()
                if existing is not None:
                    previous = json.loads(existing["result_json"])
                    if previous.get("artifact_id") != artifact_id or previous.get("content_hash") != content_hash:
                        raise ConflictError("Idempotency key was already used for a different artifact version")
                    return self._get_with_connection(connection, owner, artifact_id, int(previous["version"]))
            artifact = connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id=? AND owner=?",
                (artifact_id, owner),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("Artifact was not found")
            current = int(artifact["current_version"])
            if current != expected_current_version:
                raise ConflictError(
                    "Artifact changed since it was read",
                    details={"expected_version": expected_current_version, "current_version": current},
                )
            version = current + 1
            connection.execute(
                "INSERT INTO artifact_versions(artifact_id,version,content_hash,size_bytes,storage_path,provenance_json,created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (artifact_id, version, content_hash, len(content), storage_path, _canonical_json(provenance or {}), now),
            )
            connection.execute(
                "UPDATE artifacts SET current_version=?, updated_at=? WHERE artifact_id=?",
                (version, now, artifact_id),
            )
            result = {
                "artifact_id": artifact_id,
                "version": version,
                "filename": artifact["filename"],
                "content_hash": content_hash,
                "size_bytes": len(content),
            }
            connection.execute(
                "INSERT INTO effect_receipts(receipt_id,owner,workflow_id,step_id,idempotency_key,effect_type,target,status,result_json,created_at) "
                "VALUES (?,?,?,?,?,'artifact.commit',?,'SUCCEEDED',?,?)",
                (
                    str(uuid.uuid4()), owner, workflow_id, step_id,
                    idempotency_key or f"artifact:version:{artifact_id}:{version}",
                    f"artifact:{artifact_id}:{version}", _canonical_json(result), now,
                ),
            )
        return self.get(owner, artifact_id, version=version)

    def get(self, owner: str, artifact_id: str, *, version: int | None = None) -> dict[str, Any]:
        with self.store.transaction() as connection:
            return self._get_with_connection(connection, owner, artifact_id, version)

    def _get_with_connection(self, connection: object, owner: str, artifact_id: str, version: int | None) -> dict[str, Any]:
        artifact = connection.execute(  # type: ignore[attr-defined]
            "SELECT * FROM artifacts WHERE artifact_id=? AND owner=?", (artifact_id, owner)
        ).fetchone()
        if artifact is None:
            raise NotFoundError("Artifact was not found")
        selected = int(artifact["current_version"]) if version is None else int(version)
        row = connection.execute(  # type: ignore[attr-defined]
            "SELECT * FROM artifact_versions WHERE artifact_id=? AND version=?", (artifact_id, selected)
        ).fetchone()
        if row is None:
            raise NotFoundError("Artifact version was not found")
        return self._metadata(artifact, row)

    def read(self, owner: str, artifact_id: str, *, version: int | None = None) -> tuple[dict[str, Any], bytes]:
        metadata = self.get(owner, artifact_id, version=version)
        path = self._blob_path(str(metadata["content_hash"]))
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise NotFoundError("Artifact content is unavailable") from exc
        observed = hashlib.sha256(content).hexdigest()
        if observed != metadata["content_hash"]:
            raise RuntimeError(f"Artifact content hash mismatch for {artifact_id}")
        return metadata, content

    def list(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT a.*,v.content_hash,v.size_bytes,v.storage_path,v.provenance_json,v.created_at AS version_created_at "
                "FROM artifacts a JOIN artifact_versions v ON v.artifact_id=a.artifact_id AND v.version=a.current_version "
                "WHERE a.owner=? ORDER BY a.updated_at DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        return [self._metadata(row, row) for row in rows]

    def versions(self, owner: str, artifact_id: str) -> list[dict[str, Any]]:
        """Return the immutable version history for one owned artifact."""

        with self.store.transaction() as connection:
            artifact = connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id=? AND owner=?",
                (artifact_id, owner),
            ).fetchone()
            if artifact is None:
                raise NotFoundError("Artifact was not found")
            rows = connection.execute(
                "SELECT * FROM artifact_versions WHERE artifact_id=? ORDER BY version",
                (artifact_id,),
            ).fetchall()
        return [self._metadata(artifact, row) for row in rows]

    def _store_blob(self, content: bytes) -> tuple[str, str]:
        content_hash = hashlib.sha256(content).hexdigest()
        destination = self._blob_path(content_hash)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        relative = str(destination.relative_to(self.objects_dir))
        if destination.exists():
            observed = hashlib.sha256()
            with destination.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    observed.update(block)
            if observed.hexdigest() != content_hash:
                raise RuntimeError("Existing content-addressed object failed integrity verification")
            return content_hash, relative
        descriptor, temporary = tempfile.mkstemp(prefix=".staged-", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            if os.name == "nt":
                if destination.exists():
                    os.unlink(temporary)
                else:
                    os.replace(temporary, destination)
            else:
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    pass
                os.unlink(temporary)
                directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return content_hash, relative

    def _blob_path(self, content_hash: str) -> Path:
        if not _HASH_RE.fullmatch(content_hash):
            raise RuntimeError("Invalid object hash in artifact metadata")
        return self.objects_dir / "sha256" / content_hash[:2] / content_hash

    @staticmethod
    def _validate_metadata(owner: str, filename: str, media_type: str) -> None:
        if not owner.strip() or len(owner) > 200:
            raise ValidationError("A valid artifact owner is required")
        if not filename or len(filename) > 255 or filename in {".", ".."} or "/" in filename or "\\" in filename:
            raise ValidationError("Artifact filename must be a simple filename")
        if not media_type or len(media_type) > 200:
            raise ValidationError("A valid media type is required")

    @staticmethod
    def _metadata(artifact: object, version: object) -> dict[str, Any]:
        created = version["version_created_at"] if "version_created_at" in version.keys() else version["created_at"]  # type: ignore[attr-defined,index]
        return {
            "artifact_id": artifact["artifact_id"],  # type: ignore[index]
            "id": artifact["artifact_id"],  # type: ignore[index]
            "owner": artifact["owner"],  # type: ignore[index]
            "filename": artifact["filename"],  # type: ignore[index]
            "media_type": artifact["media_type"],  # type: ignore[index]
            "version": int(version["version"] if "version" in version.keys() else artifact["current_version"]),  # type: ignore[attr-defined,index]
            "current_version": int(artifact["current_version"]),  # type: ignore[index]
            "content_hash": version["content_hash"],  # type: ignore[index]
            "size_bytes": int(version["size_bytes"]),  # type: ignore[index]
            "provenance": json.loads(version["provenance_json"]),  # type: ignore[index]
            "created_at": created,
            "updated_at": artifact["updated_at"],  # type: ignore[index]
        }
