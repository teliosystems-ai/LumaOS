"""Verified state export, restore, and orphan-object retention controls."""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import tempfile
from typing import Any
import uuid
import zipfile

from .config import LumaConfig
from .db import LumaStore
from .errors import ValidationError


FORMAT = "luma-state-export.v1"
MANIFEST_NAME = "manifest.json"
DATABASE_NAME = "luma.sqlite3"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024 * 1024
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _safe_member(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise ValidationError("State archive contains a non-normalized path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in path.parts):
        raise ValidationError("State archive contains an unsafe path")
    return path


def _database_schema_version(path: Path) -> int:
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise ValidationError("State database failed its integrity check")
            row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValidationError("State archive contains an invalid database") from exc
    return int(row[0] or 0)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info


def export_state(config: LumaConfig, destination: str | os.PathLike[str]) -> dict[str, Any]:
    """Create a verified, atomic archive from a live local state directory."""

    output = Path(destination).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValidationError("State export destination must not already exist")
    try:
        output.relative_to(config.data_dir)
    except ValueError:
        pass
    else:
        raise ValidationError("State export must be written outside the active state directory")
    if not config.db_path.is_file() or config.db_path.is_symlink():
        raise ValidationError("Active state database is unavailable")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="luma-export-") as temporary:
        snapshot = Path(temporary) / DATABASE_NAME
        source = sqlite3.connect(config.db_path)
        target = sqlite3.connect(snapshot)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        schema_version = _database_schema_version(snapshot)

        with closing(sqlite3.connect(snapshot)) as connection:
            rows = connection.execute(
                "SELECT DISTINCT content_hash,size_bytes FROM artifact_versions ORDER BY content_hash"
            ).fetchall()
            counts = {
                "grants": int(connection.execute("SELECT COUNT(*) FROM folder_grants").fetchone()[0]),
                "artifacts": int(connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]),
                "artifact_versions": int(connection.execute("SELECT COUNT(*) FROM artifact_versions").fetchone()[0]),
                "workflows": int(connection.execute("SELECT COUNT(*) FROM workflows").fetchone()[0]),
                "receipts": int(connection.execute("SELECT COUNT(*) FROM effect_receipts").fetchone()[0]),
            }

        files: list[dict[str, Any]] = []
        database_bytes = snapshot.read_bytes()
        files.append({"path": DATABASE_NAME, "size_bytes": len(database_bytes), "sha256": _sha256_bytes(database_bytes)})
        objects: list[tuple[str, bytes]] = []
        for raw_hash, expected_size in rows:
            content_hash = str(raw_hash)
            if not _HASH_RE.fullmatch(content_hash):
                raise ValidationError("State database contains an invalid object digest")
            object_path = config.objects_dir / "sha256" / content_hash[:2] / content_hash
            if object_path.is_symlink() or not object_path.is_file():
                raise ValidationError("State database references unavailable object content")
            content = object_path.read_bytes()
            if len(content) != int(expected_size) or _sha256_bytes(content) != content_hash:
                raise ValidationError("State object failed size or digest verification")
            member = f"objects/sha256/{content_hash[:2]}/{content_hash}"
            files.append({"path": member, "size_bytes": len(content), "sha256": content_hash})
            objects.append((member, content))

        manifest = {
            "format": FORMAT,
            "created_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "application_version": "0.1.0",
            "database_schema_version": schema_version,
            "counts": counts,
            "files": files,
        }
        descriptor, temporary_name = tempfile.mkstemp(prefix=".luma-state-", suffix=".zip", dir=output.parent)
        os.close(descriptor)
        temporary_archive = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary_archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                archive.writestr(_zip_info(MANIFEST_NAME), _canonical_json(manifest))
                archive.writestr(_zip_info(DATABASE_NAME), database_bytes)
                for member, content in objects:
                    archive.writestr(_zip_info(member), content)
            with temporary_archive.open("rb") as stream:
                os.fsync(stream.fileno())
            os.chmod(temporary_archive, 0o600)
            os.replace(temporary_archive, output)
        finally:
            temporary_archive.unlink(missing_ok=True)
    return {
        "format": FORMAT,
        "path": str(output),
        "sha256": _sha256_file(output),
        "size_bytes": output.stat().st_size,
        "database_schema_version": schema_version,
        "counts": counts,
        "file_count": len(files),
    }


def inspect_state_archive(archive_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Validate an archive and return its authenticated manifest metadata."""

    path = Path(archive_path).expanduser().absolute()
    if path.is_symlink() or not path.is_file():
        raise ValidationError("State archive is unavailable")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValidationError("State archive exceeds the supported size limit")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValidationError("State archive contains duplicate paths")
            for info in infos:
                _safe_member(info.filename)
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise ValidationError("State archive cannot contain symbolic links")
            if MANIFEST_NAME not in names:
                raise ValidationError("State archive manifest is missing")
            if archive.getinfo(MANIFEST_NAME).file_size > 1024 * 1024:
                raise ValidationError("State archive manifest is too large")
            manifest = json.loads(archive.read(MANIFEST_NAME))
            if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
                raise ValidationError("State archive format is unsupported")
            entries = manifest.get("files")
            if not isinstance(entries, list) or not entries:
                raise ValidationError("State archive manifest has no file inventory")
            expected_names = {MANIFEST_NAME}
            total_size = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValidationError("State archive file inventory is invalid")
                member = _safe_member(str(entry.get("path", ""))).as_posix()
                digest = entry.get("sha256")
                size = entry.get("size_bytes")
                if not isinstance(digest, str) or not _HASH_RE.fullmatch(digest):
                    raise ValidationError("State archive inventory contains an invalid digest")
                if not isinstance(size, int) or size < 0:
                    raise ValidationError("State archive inventory contains an invalid size")
                if member in expected_names:
                    raise ValidationError("State archive inventory contains duplicate paths")
                expected_names.add(member)
                total_size += size
                if total_size > MAX_ARCHIVE_BYTES:
                    raise ValidationError("State archive expands beyond the supported size limit")
                try:
                    info = archive.getinfo(member)
                except KeyError as exc:
                    raise ValidationError("State archive is missing inventoried content") from exc
                if info.file_size != size:
                    raise ValidationError("State archive content size does not match its manifest")
                content = archive.read(member)
                if _sha256_bytes(content) != digest:
                    raise ValidationError("State archive content digest does not match its manifest")
            if set(names) != expected_names:
                raise ValidationError("State archive contains unlisted content")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("State archive is malformed") from exc
    return manifest


def restore_state(archive_path: str | os.PathLike[str], destination: str | os.PathLike[str]) -> dict[str, Any]:
    """Restore a verified archive atomically into a new state directory."""

    archive_file = Path(archive_path).expanduser().absolute()
    target = Path(destination).expanduser().absolute()
    if target.exists() or target.is_symlink():
        raise ValidationError("Restore destination must not already exist")
    manifest = inspect_state_archive(archive_file)
    schema_version = manifest.get("database_schema_version")
    if not isinstance(schema_version, int) or schema_version > LumaStore.latest_schema_version:
        raise ValidationError("State archive database is newer than this Luma OS build")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".luma-restore-", dir=target.parent))
    try:
        os.chmod(temporary, 0o700)
        with zipfile.ZipFile(archive_file, "r") as archive:
            for entry in manifest["files"]:
                member = _safe_member(entry["path"])
                output = temporary.joinpath(*member.parts)
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                output.write_bytes(archive.read(member.as_posix()))
                os.chmod(output, 0o600)
        database = temporary / DATABASE_NAME
        observed_version = _database_schema_version(database)
        if observed_version != schema_version:
            raise ValidationError("Restored database schema does not match the archive manifest")
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {
        "format": FORMAT,
        "path": str(target),
        "database_schema_version": schema_version,
        "counts": manifest.get("counts", {}),
        "source_archive_sha256": _sha256_file(archive_file),
    }


def prune_unreferenced_objects(config: LumaConfig, *, apply: bool = False) -> dict[str, Any]:
    """Report or remove only content objects that no artifact version references."""

    store = LumaStore(config.db_path)
    with store.transaction() as connection:
        referenced = {str(row[0]) for row in connection.execute("SELECT DISTINCT content_hash FROM artifact_versions")}
    root = config.objects_dir / "sha256"
    candidates: list[Path] = []
    reclaimed = 0
    if root.exists():
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValidationError("Object store contains a symbolic link")
            if not path.is_file():
                continue
            if not _HASH_RE.fullmatch(path.name):
                raise ValidationError("Object store contains a non-canonical file")
            if path.name not in referenced:
                candidates.append(path)
                reclaimed += path.stat().st_size
    if apply:
        for path in candidates:
            path.unlink()
        if root.exists():
            for directory in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
                try:
                    directory.rmdir()
                except OSError:
                    pass
    result = {
        "mode": "applied" if apply else "dry_run",
        "object_count": len(candidates),
        "reclaimable_bytes": reclaimed,
        "objects": [str(path.relative_to(config.objects_dir).as_posix()) for path in candidates],
    }
    with store.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO state_maintenance_runs(run_id,operation,mode,object_count,reclaimable_bytes,details_json,created_at) "
            "VALUES (?,'object_retention',?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                result["mode"],
                result["object_count"],
                result["reclaimable_bytes"],
                json.dumps({"objects": result["objects"]}, sort_keys=True, separators=(",", ":")),
                datetime.now(UTC).isoformat(timespec="milliseconds"),
            ),
        )
    return result
