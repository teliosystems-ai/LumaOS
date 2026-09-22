"""Scoped folder enrollment with descriptor-relative, no-symlink reads."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePath
import stat
import uuid

from .db import LumaStore, utc_now
from .errors import AuthorizationError, NotFoundError, ValidationError


@dataclass(frozen=True, slots=True)
class SafeFile:
    grant_id: str
    relative_path: str
    size_bytes: int
    content: bytes


class FolderGrantService:
    """Owns explicit per-user grants and safe file reads.

    Every path component is opened relative to a verified directory descriptor
    with ``O_NOFOLLOW``. Returning a normal path is intentionally avoided: a
    caller cannot accidentally reopen a checked path through a changed symlink.
    """

    def __init__(self, store: LumaStore, *, max_source_bytes: int = 10 * 1024 * 1024) -> None:
        self.store = store
        self.max_source_bytes = max_source_bytes

    @staticmethod
    def _validate_owner(owner: str) -> str:
        cleaned = owner.strip()
        if not cleaned or len(cleaned) > 200 or "\x00" in cleaned:
            raise ValidationError("A valid owner identity is required")
        return cleaned

    @staticmethod
    def _parts(relative_path: str) -> tuple[str, ...]:
        if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
            raise ValidationError("A non-empty relative path is required")
        path = PurePath(relative_path)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise ValidationError("Path must stay within the enrolled folder", details={"path": relative_path})
        if os.name == "nt" and (":" in relative_path or relative_path.startswith(("\\", "/"))):
            raise ValidationError("Path must be relative to the enrolled folder")
        return tuple(path.parts)

    def enroll(
        self,
        owner: str,
        path: str | os.PathLike[str],
        *,
        display_name: str | None = None,
        scope: str = "read",
    ) -> dict[str, object]:
        owner = self._validate_owner(owner)
        if scope not in {"read", "read_write"}:
            raise ValidationError("Grant scope must be 'read' or 'read_write'")
        requested = Path(path).expanduser()
        try:
            root = requested.resolve(strict=True)
            info = root.stat()
        except (FileNotFoundError, OSError) as exc:
            raise ValidationError("Folder does not exist or cannot be inspected", details={"path": str(requested)}) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ValidationError("Only folders can be enrolled", details={"path": str(root)})
        label = (display_name or root.name or str(root)).strip()
        if not label or len(label) > 200:
            raise ValidationError("Display name must be between 1 and 200 characters")

        with self.store.transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM folder_grants WHERE owner = ? AND root_path = ?",
                (owner, str(root)),
            ).fetchone()
            now = utc_now()
            if existing is not None:
                created_at = existing["created_at"] if existing["revoked_at"] is None else now
                connection.execute(
                    "UPDATE folder_grants SET root_device=?, root_inode=?, display_name=?, scope=?, created_at=?, revoked_at=NULL "
                    "WHERE grant_id=?",
                    (info.st_dev, info.st_ino, label, scope, created_at, existing["grant_id"]),
                )
                row = connection.execute("SELECT * FROM folder_grants WHERE grant_id=?", (existing["grant_id"],)).fetchone()
            else:
                grant_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO folder_grants(grant_id,owner,root_path,root_device,root_inode,display_name,scope,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (grant_id, owner, str(root), info.st_dev, info.st_ino, label, scope, now),
                )
                row = connection.execute("SELECT * FROM folder_grants WHERE grant_id=?", (grant_id,)).fetchone()
        return self._row(row)

    def list(self, owner: str, *, include_revoked: bool = False) -> list[dict[str, object]]:
        owner = self._validate_owner(owner)
        where = "owner = ?" if include_revoked else "owner = ? AND revoked_at IS NULL"
        with self.store.transaction() as connection:
            rows = connection.execute(
                f"SELECT * FROM folder_grants WHERE {where} ORDER BY created_at DESC",  # noqa: S608 - fixed clauses
                (owner,),
            ).fetchall()
        return [self._row(row) for row in rows]

    def get(self, owner: str, grant_id: str, *, require_active: bool = True) -> dict[str, object]:
        owner = self._validate_owner(owner)
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM folder_grants WHERE grant_id=? AND owner=?",
                (grant_id, owner),
            ).fetchone()
        if row is None:
            raise NotFoundError("Folder grant was not found")
        if require_active and row["revoked_at"] is not None:
            raise AuthorizationError("Folder grant has been revoked")
        return self._row(row)

    def revoke(self, owner: str, grant_id: str) -> dict[str, object]:
        self.get(owner, grant_id)
        with self.store.transaction(write=True) as connection:
            connection.execute(
                "UPDATE folder_grants SET revoked_at=? WHERE grant_id=? AND owner=? AND revoked_at IS NULL",
                (utc_now(), grant_id, owner),
            )
            row = connection.execute("SELECT * FROM folder_grants WHERE grant_id=?", (grant_id,)).fetchone()
        return self._row(row)

    def inspect_file(self, owner: str, grant_id: str, relative_path: str) -> dict[str, object]:
        descriptor, info = self._open_file(owner, grant_id, relative_path)
        os.close(descriptor)
        return {"grant_id": grant_id, "relative_path": relative_path, "size_bytes": int(info.st_size)}

    def read_file(self, owner: str, grant_id: str, relative_path: str) -> SafeFile:
        descriptor, initial = self._open_file(owner, grant_id, relative_path)
        try:
            chunks: list[bytes] = []
            remaining = int(initial.st_size)
            while remaining:
                block = os.read(descriptor, min(remaining, 1024 * 1024))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            content = b"".join(chunks)
            final = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity = (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
        final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
        if len(content) != initial.st_size or identity != final_identity:
            raise ValidationError("Source file changed while it was being read", details={"path": relative_path})
        return SafeFile(grant_id, relative_path, int(initial.st_size), content)

    def _open_file(self, owner: str, grant_id: str, relative_path: str) -> tuple[int, os.stat_result]:
        grant = self.get(owner, grant_id)
        parts = self._parts(relative_path)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        root_fd = -1
        current_fd = -1
        try:
            root_fd = os.open(str(grant["root_path"]), os.O_RDONLY | directory_flag | no_follow | close_on_exec)
            current_fd = root_fd
            root_stat = os.fstat(root_fd)
            if root_stat.st_dev != grant["root_device"] or root_stat.st_ino != grant["root_inode"]:
                raise AuthorizationError("Enrolled folder identity has changed; enroll it again")
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | directory_flag | no_follow | close_on_exec, dir_fd=current_fd)
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = next_fd
            file_fd = os.open(parts[-1], os.O_RDONLY | no_follow | close_on_exec, dir_fd=current_fd)
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                os.close(file_fd)
                raise ValidationError("Source must be a regular file", details={"path": relative_path})
            if info.st_size > self.max_source_bytes:
                os.close(file_fd)
                raise ValidationError(
                    "Source file exceeds the configured size limit",
                    details={"path": relative_path, "size_bytes": info.st_size, "limit_bytes": self.max_source_bytes},
                )
            return file_fd, info
        except FileNotFoundError as exc:
            raise NotFoundError("Source file was not found", details={"path": relative_path}) from exc
        except OSError as exc:
            raise AuthorizationError(
                "Source path could not be opened safely; symbolic links are not followed",
                details={"path": relative_path},
            ) from exc
        finally:
            if current_fd >= 0 and current_fd != root_fd:
                os.close(current_fd)
            if root_fd >= 0:
                os.close(root_fd)

    @staticmethod
    def _row(row: object) -> dict[str, object]:
        scope = row["scope"]  # type: ignore[index]
        return {
            "grant_id": row["grant_id"],  # type: ignore[index]
            "id": row["grant_id"],  # type: ignore[index]
            "owner": row["owner"],  # type: ignore[index]
            "root_path": row["root_path"],  # type: ignore[index]
            "root": row["root_path"],  # type: ignore[index]
            "root_device": int(row["root_device"]),  # type: ignore[index]
            "root_inode": int(row["root_inode"]),  # type: ignore[index]
            "display_name": row["display_name"],  # type: ignore[index]
            "scope": scope,
            "permissions": ["read", "index"] if scope == "read" else ["read", "index", "write", "export"],
            "created_at": row["created_at"],  # type: ignore[index]
            "revoked_at": row["revoked_at"],  # type: ignore[index]
        }
