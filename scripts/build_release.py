#!/usr/bin/env python3
"""Build deterministic Luma OS source archives with SHA-256 checksums."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
VERSION = MANIFEST["version"]
ARCHIVE_ROOT = f"luma-os-{VERSION}"
FORBIDDEN_SUFFIXES = {".gguf", ".safetensors", ".onnx", ".ckpt", ".pt", ".pth"}


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from exc
    return max(0, value)


def included_files() -> list[Path]:
    files: set[Path] = set()
    for entry in MANIFEST["release_inputs"]:
        path = ROOT / entry
        if not path.exists():
            raise SystemExit(f"release input does not exist: {entry}")
        if path.is_symlink():
            raise SystemExit(f"release input cannot be a symlink: {entry}")
        if path.is_file():
            files.add(path)
            continue
        for candidate in path.rglob("*"):
            if candidate.is_symlink():
                raise SystemExit(f"release input contains a symlink: {candidate.relative_to(ROOT)}")
            if candidate.is_file() and "__pycache__" not in candidate.parts:
                files.add(candidate)
    selected = sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())
    forbidden = [item for item in selected if item.suffix.lower() in FORBIDDEN_SUFFIXES]
    if forbidden:
        names = ", ".join(str(item.relative_to(ROOT)) for item in forbidden)
        raise SystemExit(f"model/binary weight files cannot be packaged: {names}")
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
    files = included_files()
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
