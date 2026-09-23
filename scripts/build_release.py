#!/usr/bin/env python3
"""Build deterministic Luma OS source archives with SHA-256 checksums."""

from __future__ import annotations

import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile
import tempfile
from typing import BinaryIO
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
VERSION = MANIFEST["version"]
ARCHIVE_ROOT = f"luma-os-{VERSION}"
FORBIDDEN_SUFFIXES = {".gguf", ".safetensors", ".onnx", ".ckpt", ".pt", ".pth"}


class ReleaseProvenanceError(RuntimeError):
    """Raised when the manifest cannot be mapped to tracked repository files."""


@dataclass(frozen=True)
class ArchiveEntry:
    """One immutable, repository-relative release payload."""

    relative: PurePosixPath
    data: bytes
    mode: int


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from exc
    if not 0 <= value <= 0xFFFFFFFF:
        raise SystemExit("SOURCE_DATE_EPOCH must fit the unsigned 32-bit gzip timestamp")
    return value


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
    executable_files = manifest_paths(manifest, "executable_release_files")
    required_files = manifest_paths(manifest, "required_release_files")
    exclusions = manifest_paths(manifest, "excluded_from_release")
    tracked_paths = git_tracked_files(root) if tracked is None else tracked

    if not release_files:
        raise ReleaseProvenanceError("release manifest release_files must not be empty")
    undeclared_executables = set(executable_files) - set(release_files)
    if undeclared_executables:
        names = ", ".join(
            path.as_posix()
            for path in sorted(undeclared_executables, key=PurePosixPath.as_posix)
        )
        raise ReleaseProvenanceError(
            f"executable release files are absent from release inventory: {names}"
        )

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


def _git_result(
    arguments: list[str],
    *,
    root: Path,
    input_data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ReleaseProvenanceError(f"cannot query Git release provenance: {exc}") from exc


def _git_error(result: subprocess.CompletedProcess[bytes], action: str) -> ReleaseProvenanceError:
    detail = os.fsdecode(result.stderr).strip()
    suffix = f": {detail}" if detail else ""
    return ReleaseProvenanceError(f"cannot {action}{suffix}")


def _git_head(root: Path) -> str:
    result = _git_result(["rev-parse", "--verify", "HEAD^{commit}"], root=root)
    if result.returncode:
        raise _git_error(result, "resolve the release-source commit")
    commit = os.fsdecode(result.stdout).strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ReleaseProvenanceError("Git returned an invalid release-source commit")
    return commit


def _require_clean_release_tree(
    root: Path,
    commit: str,
    release_files: tuple[PurePosixPath, ...],
) -> None:
    result = _git_result(
        [
            "-c",
            "core.filemode=false",
            "-c",
            "core.autocrlf=input",
            "diff",
            "--quiet",
            commit,
            "--",
            *(path.as_posix() for path in release_files),
        ],
        root=root,
    )
    if result.returncode == 1:
        raise ReleaseProvenanceError(
            "release inventory has staged or unstaged content changes relative to HEAD"
        )
    if result.returncode:
        raise _git_error(result, "compare the release inventory with HEAD")


def _git_tree_records(
    root: Path,
    commit: str,
    release_files: tuple[PurePosixPath, ...],
) -> dict[PurePosixPath, tuple[str, str]]:
    """Return ``path -> (mode, object id)`` for regular blobs at a commit."""

    wanted = set(release_files)
    result = _git_result(["ls-tree", "-rz", "--full-tree", commit], root=root)
    if result.returncode:
        raise _git_error(result, "read the release-source tree")
    records: dict[PurePosixPath, tuple[str, str]] = {}
    for raw_record in result.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            raw_metadata, raw_path = raw_record.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = raw_metadata.split(b" ", 2)
        except ValueError as exc:
            raise ReleaseProvenanceError("Git returned a malformed release-source tree") from exc
        relative = PurePosixPath(os.fsdecode(raw_path))
        if relative not in wanted:
            continue
        mode = raw_mode.decode("ascii")
        object_type = raw_type.decode("ascii")
        object_id = raw_object_id.decode("ascii")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ReleaseProvenanceError(
                f"release-source entry is not a regular 100644/100755 blob: {relative}"
            )
        records[relative] = (mode, object_id)
    missing = sorted(wanted - set(records), key=PurePosixPath.as_posix)
    if missing:
        names = ", ".join(path.as_posix() for path in missing)
        raise ReleaseProvenanceError(f"release files are absent from HEAD: {names}")
    return records


def _git_blob_payloads(
    root: Path,
    records: dict[PurePosixPath, tuple[str, str]],
    release_files: tuple[PurePosixPath, ...],
) -> dict[PurePosixPath, bytes]:
    requests = b"".join(
        records[path][1].encode("ascii") + b"\n" for path in release_files
    )
    result = _git_result(["cat-file", "--batch"], root=root, input_data=requests)
    if result.returncode:
        raise _git_error(result, "read committed release blobs")
    output = result.stdout
    offset = 0
    payloads: dict[PurePosixPath, bytes] = {}
    for relative in release_files:
        header_end = output.find(b"\n", offset)
        if header_end < 0:
            raise ReleaseProvenanceError("Git returned a truncated committed-blob response")
        header = output[offset:header_end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":
            raise ReleaseProvenanceError(
                f"Git did not return a regular blob for release file: {relative}"
            )
        try:
            size = int(header[2])
        except ValueError as exc:
            raise ReleaseProvenanceError("Git returned an invalid committed-blob size") from exc
        data_start = header_end + 1
        data_end = data_start + size
        if data_end >= len(output) or output[data_end : data_end + 1] != b"\n":
            raise ReleaseProvenanceError("Git returned a truncated committed blob")
        payloads[relative] = output[data_start:data_end]
        offset = data_end + 1
    if offset != len(output):
        raise ReleaseProvenanceError("Git returned unexpected committed-blob data")
    return payloads


def release_snapshot(
    files: list[Path],
    *,
    root: Path,
    manifest: dict[str, object],
    tracked: set[PurePosixPath] | None,
) -> tuple[tuple[ArchiveEntry, ...], str | None]:
    """Freeze archive bytes and modes from HEAD, or from a Git-less extracted archive."""

    release_files = manifest_paths(manifest, "release_files")
    executable_files = frozenset(manifest_paths(manifest, "executable_release_files"))
    selected = {
        PurePosixPath(path.relative_to(root).as_posix()): path
        for path in files
    }
    if set(selected) != set(release_files):
        raise ReleaseProvenanceError("selected release files do not match the manifest inventory")

    if tracked is None:
        payloads = {relative: selected[relative].read_bytes() for relative in release_files}
        source_commit = None
    else:
        source_commit = _git_head(root)
        _require_clean_release_tree(root, source_commit, release_files)
        records = _git_tree_records(root, source_commit, release_files)
        tree_executables = {
            relative for relative, (mode, _) in records.items() if mode == "100755"
        }
        if tree_executables != executable_files:
            missing = sorted(executable_files - tree_executables, key=PurePosixPath.as_posix)
            extra = sorted(tree_executables - executable_files, key=PurePosixPath.as_posix)
            raise ReleaseProvenanceError(
                "release manifest executable modes differ from HEAD "
                f"(missing={list(map(str, missing))}, extra={list(map(str, extra))})"
            )
        payloads = _git_blob_payloads(root, records, release_files)

    entries = tuple(
        ArchiveEntry(
            relative=relative,
            data=payloads[relative],
            mode=0o755 if relative in executable_files else 0o644,
        )
        for relative in release_files
    )
    return entries, source_commit


def build_tar(
    destination: Path,
    entries: tuple[ArchiveEntry, ...],
    epoch: int,
    *,
    archive_root: str = ARCHIVE_ROOT,
) -> None:
    with tempfile.SpooledTemporaryFile() as uncompressed:
        with tarfile.open(fileobj=uncompressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for entry in entries:
                info = tarfile.TarInfo(f"{archive_root}/{entry.relative.as_posix()}")
                info.size = len(entry.data)
                info.mtime = epoch
                info.mode = entry.mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                with tempfile.SpooledTemporaryFile() as source:
                    source.write(entry.data)
                    source.seek(0)
                    archive.addfile(info, source)
        uncompressed.seek(0)
        _write_stored_gzip(destination, uncompressed, epoch)


def _write_stored_gzip(destination: Path, source: BinaryIO, epoch: int) -> None:
    """Write a valid gzip stream without runtime-dependent zlib compression."""

    with destination.open("wb") as output:
        output.write(b"\x1f\x8b\x08\x00")
        output.write(struct.pack("<I", epoch))
        output.write(b"\x00\xff")
        checksum = 0
        total_size = 0
        block = source.read(65535)
        if not block:
            output.write(b"\x01\x00\x00\xff\xff")
        while block:
            next_block = source.read(65535)
            output.write(b"\x01" if not next_block else b"\x00")
            output.write(struct.pack("<HH", len(block), len(block) ^ 0xFFFF))
            output.write(block)
            checksum = binascii.crc32(block, checksum)
            total_size = (total_size + len(block)) & 0xFFFFFFFF
            block = next_block
        output.write(struct.pack("<II", checksum & 0xFFFFFFFF, total_size))


def build_zip(
    destination: Path,
    entries: tuple[ArchiveEntry, ...],
    epoch: int,
    *,
    archive_root: str = ARCHIVE_ROOT,
) -> None:
    import datetime

    safe_epoch = max(epoch, 315532800)  # ZIP timestamps begin at 1980-01-01.
    timestamp = datetime.datetime.fromtimestamp(safe_epoch, datetime.UTC).timetuple()[:6]
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for entry in entries:
            info = zipfile.ZipInfo(
                f"{archive_root}/{entry.relative.as_posix()}", timestamp
            )
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.flag_bits = 0
            info.internal_attr = 0
            info.external_attr = (0o100000 | entry.mode) << 16
            archive.writestr(info, entry.data)


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
        tracked = git_tracked_files()
        files = included_files(tracked=tracked)
        entries, source_commit = release_snapshot(
            files,
            root=ROOT,
            manifest=MANIFEST,
            tracked=tracked,
        )
    except ReleaseProvenanceError as exc:
        raise SystemExit(str(exc)) from exc
    epoch = source_date_epoch()
    DIST.mkdir(exist_ok=True)
    tar_path = DIST / f"{ARCHIVE_ROOT}.tar.gz"
    zip_path = DIST / f"{ARCHIVE_ROOT}.zip"
    build_tar(tar_path, entries, epoch)
    build_zip(zip_path, entries, epoch)
    lines = [f"{digest(path)}  {path.name}" for path in (tar_path, zip_path)]
    (DIST / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Built {len(files)} files into:")
    print(f"  source: {source_commit or 'Git-less canonical archive bytes'}")
    print(f"  {tar_path.relative_to(ROOT)}")
    print(f"  {zip_path.relative_to(ROOT)}")
    print("  dist/SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
