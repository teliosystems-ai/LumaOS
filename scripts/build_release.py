#!/usr/bin/env python3
"""Build deterministic Luma OS source archives with SHA-256 checksums."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
VERSION = MANIFEST["version"]
ARCHIVE_ROOT = f"luma-os-{VERSION}"
FORBIDDEN_SUFFIXES = {".gguf", ".safetensors", ".onnx", ".ckpt", ".pt", ".pth"}


class ReleaseProvenanceError(RuntimeError):
    """Raised when the manifest cannot be mapped to tracked repository files."""


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from exc
    return max(0, value)


def manifest_paths(manifest: dict[str, object], field: str) -> tuple[PurePosixPath, ...]:
    """Return validated repository-relative paths from a manifest list."""

    entries = manifest.get(field)
    if not isinstance(entries, list):
        raise ReleaseProvenanceError(f"release manifest {field} must be a list")
    paths: list[PurePosixPath] = []
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            raise ReleaseProvenanceError(f"release manifest {field} entries must be non-empty strings")
        path = PurePosixPath(entry)
        if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts or "\\" in entry:
            raise ReleaseProvenanceError(
                f"release manifest {field} path must be normalized and repository-relative: {entry!r}"
            )
        if path.as_posix() != entry:
            raise ReleaseProvenanceError(
                f"release manifest {field} path must use normalized POSIX syntax: {entry!r}"
            )
        paths.append(path)
    if len(set(paths)) != len(paths):
        raise ReleaseProvenanceError(f"release manifest {field} contains duplicate paths")
    return tuple(paths)


def git_tracked_files(root: Path = ROOT) -> set[PurePosixPath] | None:
    """Return Git-index paths, or ``None`` for a source tree without repository metadata."""

    try:
        repository = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        if (root / ".git").exists():
            raise ReleaseProvenanceError(f"cannot query Git release provenance: {exc}") from exc
        return None
    if repository.returncode:
        if (root / ".git").exists():
            detail = os.fsdecode(repository.stderr).strip()
            suffix = f": {detail}" if detail else ""
            raise ReleaseProvenanceError(f"cannot query Git release provenance{suffix}")
        return None
    repository_root = Path(os.fsdecode(repository.stdout).strip())
    if repository_root.resolve() != root.resolve():
        return None

    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--full-name", "-z", "--"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ReleaseProvenanceError(f"cannot query Git release provenance: {exc}") from exc
    if result.returncode:
        detail = os.fsdecode(result.stderr).strip()
        suffix = f": {detail}" if detail else ""
        raise ReleaseProvenanceError(f"cannot query Git release provenance{suffix}")
    return {
        PurePosixPath(os.fsdecode(raw_path))
        for raw_path in result.stdout.split(b"\0")
        if raw_path
    }


def path_is_within(path: PurePosixPath, parent: PurePosixPath) -> bool:
    return path == parent or parent in path.parents


def reject_symlink_components(root: Path, relative: PurePosixPath, label: str) -> Path:
    """Resolve a manifest path without allowing any component to be a symlink."""

    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ReleaseProvenanceError(f"{label} contains a symlink: {relative}")
    return current


def included_files(
    root: Path = ROOT,
    manifest: dict[str, object] = MANIFEST,
    tracked: set[PurePosixPath] | None = None,
) -> list[Path]:
    """Select only canonical inventory files and verify them against Git when available."""

    release_inputs = manifest_paths(manifest, "release_inputs")
    release_files = manifest_paths(manifest, "release_files")
    required_files = manifest_paths(manifest, "required_release_files")
    exclusions = manifest_paths(manifest, "excluded_from_release")
    tracked_paths = git_tracked_files(root) if tracked is None else tracked

    if not release_files:
        raise ReleaseProvenanceError("release manifest release_files must not be empty")

    for entry in release_inputs:
        path = reject_symlink_components(root, entry, "release input")
        if not path.exists():
            raise ReleaseProvenanceError(f"release input does not exist: {entry}")
        if path.is_file() and entry not in release_files:
            raise ReleaseProvenanceError(f"file release input is absent from release inventory: {entry}")

    for required in required_files:
        if not any(path_is_within(required, entry) for entry in release_inputs):
            raise ReleaseProvenanceError(f"required release file is outside release inputs: {required}")
        if any(path_is_within(required, exclusion) for exclusion in exclusions):
            raise ReleaseProvenanceError(f"required release file is excluded by the manifest: {required}")
        path = reject_symlink_components(root, required, "required release file")
        if not path.is_file():
            raise ReleaseProvenanceError(f"required release file is missing or not a regular file: {required}")
        if required not in release_files:
            raise ReleaseProvenanceError(f"required release file is absent from release inventory: {required}")

    for relative in release_files:
        if not any(path_is_within(relative, entry) for entry in release_inputs):
            raise ReleaseProvenanceError(f"release inventory file is outside release inputs: {relative}")
        if any(path_is_within(relative, exclusion) for exclusion in exclusions):
            raise ReleaseProvenanceError(f"release inventory file is excluded by the manifest: {relative}")

    if tracked_paths is not None:
        untracked = sorted(set(release_files) - tracked_paths, key=PurePosixPath.as_posix)
        if untracked:
            names = ", ".join(path.as_posix() for path in untracked)
            raise ReleaseProvenanceError(f"release inventory files are not tracked by Git: {names}")
        tracked_in_scope = {
            path
            for path in tracked_paths
            if any(path_is_within(path, entry) for entry in release_inputs)
            and not any(path_is_within(path, exclusion) for exclusion in exclusions)
            and "__pycache__" not in path.parts
        }
        unlisted = sorted(tracked_in_scope - set(release_files), key=PurePosixPath.as_posix)
        if unlisted:
            names = ", ".join(path.as_posix() for path in unlisted)
            raise ReleaseProvenanceError(f"tracked release files are absent from release inventory: {names}")

    selected: list[Path] = []
    for relative in release_files:
        path = reject_symlink_components(root, relative, "release inventory path")
        if not path.is_file():
            raise ReleaseProvenanceError(f"tracked release file is missing or not a regular file: {relative}")
        selected.append(path)

    forbidden = [item for item in selected if item.suffix.lower() in FORBIDDEN_SUFFIXES]
    if forbidden:
        names = ", ".join(item.relative_to(root).as_posix() for item in forbidden)
        raise ReleaseProvenanceError(f"model/binary weight files cannot be packaged: {names}")
    return selected


def archive_mode(path: Path) -> int:
    executable = bool(path.stat().st_mode & stat.S_IXUSR)
    return 0o755 if executable else 0o644


def build_tar(destination: Path, files: list[Path], epoch: int) -> None:
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in files:
                    relative = path.relative_to(ROOT).as_posix()
                    data = path.read_bytes()
                    info = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{relative}")
                    info.size = len(data)
                    info.mtime = epoch
                    info.mode = archive_mode(path)
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    with tempfile.SpooledTemporaryFile() as source:
                        source.write(data)
                        source.seek(0)
                        archive.addfile(info, source)


def build_zip(destination: Path, files: list[Path], epoch: int) -> None:
    import datetime

    safe_epoch = max(epoch, 315532800)  # ZIP timestamps begin at 1980-01-01.
    timestamp = datetime.datetime.fromtimestamp(safe_epoch, datetime.UTC).timetuple()[:6]
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{relative}", timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = archive_mode(path) << 16
            archive.writestr(info, path.read_bytes())


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def main() -> int:
    if MANIFEST.get("project") != "luma-os":
        raise SystemExit("invalid release manifest project")
    try:
        files = included_files()
    except ReleaseProvenanceError as exc:
        raise SystemExit(str(exc)) from exc
    epoch = source_date_epoch()
    DIST.mkdir(exist_ok=True)
    tar_path = DIST / f"{ARCHIVE_ROOT}.tar.gz"
    zip_path = DIST / f"{ARCHIVE_ROOT}.zip"
    build_tar(tar_path, files, epoch)
    build_zip(zip_path, files, epoch)
    lines = [f"{digest(path)}  {path.name}" for path in (tar_path, zip_path)]
    (DIST / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Built {len(files)} files into:")
    print(f"  {tar_path.relative_to(ROOT)}")
    print(f"  {zip_path.relative_to(ROOT)}")
    print("  dist/SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
