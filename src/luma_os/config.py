"""Configuration and private data-directory setup for the local MVP."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Mapping

from .errors import ValidationError


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ValidationError(f"{name} must be greater than zero")
    return parsed


@dataclass(frozen=True, slots=True)
class LumaConfig:
    """Resolved runtime configuration.

    The control plane binds to loopback by default. ``server.py`` separately
    enforces an explicit unsafe override before accepting a non-loopback host.
    """

    data_dir: Path
    db_path: Path
    objects_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    max_source_bytes: int = 10 * 1024 * 1024
    model_endpoint: str | None = None
    model_name: str | None = None
    model_api_key: str | None = None

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        data_dir: str | os.PathLike[str] | None = None,
    ) -> "LumaConfig":
        values = os.environ if env is None else env
        if data_dir is None:
            configured = values.get("LUMA_HOME")
            if configured:
                root = Path(configured)
            else:
                state_home = values.get("XDG_STATE_HOME")
                root = Path(state_home) / "luma-os" if state_home else Path.home() / ".local" / "state" / "luma-os"
        else:
            root = Path(data_dir)
        root = root.expanduser().absolute()
        port = _positive_int(values.get("LUMA_PORT", "8765"), "LUMA_PORT")
        if port > 65535:
            raise ValidationError("LUMA_PORT must be at most 65535")
        max_bytes = _positive_int(values.get("LUMA_MAX_SOURCE_BYTES", str(10 * 1024 * 1024)), "LUMA_MAX_SOURCE_BYTES")
        return cls(
            data_dir=root,
            db_path=root / "luma.sqlite3",
            objects_dir=root / "objects",
            host=values.get("LUMA_HOST", "127.0.0.1"),
            port=port,
            max_source_bytes=max_bytes,
            model_endpoint=values.get("LUMA_MODEL_ENDPOINT") or None,
            model_name=values.get("LUMA_MODEL_NAME") or None,
            model_api_key=values.get("LUMA_MODEL_API_KEY") or None,
        )

    def ensure_directories(self) -> None:
        """Create private runtime directories and tighten POSIX permissions.

        Windows does not implement POSIX directory mode bits: ``chmod(0o700)``
        is not an ACL operation and ``stat`` reports ``0o777``.  On Windows we
        still reject symlinks, junctions, and other reparse points, while the
        directory's inherited DACL remains the platform security boundary.
        """

        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._secure_directory(self.data_dir)
        # Validate the state root before creating anything below it.  This
        # prevents an existing root reparse point from redirecting even the
        # objects-directory creation outside the configured location.
        self.objects_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._secure_directory(self.objects_dir)

    @staticmethod
    def _secure_directory(directory: Path) -> None:
        info = os.lstat(directory)
        attributes = int(getattr(info, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if directory.is_symlink() or attributes & reparse_flag:
            raise ValidationError(
                f"Runtime directory cannot be a symbolic link or junction: {directory}"
            )
        if not directory.is_dir():
            raise ValidationError(f"Runtime path is not a directory: {directory}")
        if os.name == "nt":
            return
        try:
            directory.chmod(0o700)
        except PermissionError as exc:
            raise ValidationError(f"Cannot secure runtime directory: {directory}") from exc
        if directory.stat().st_mode & 0o077:
            raise ValidationError(f"Runtime directory permissions are not private: {directory}")
