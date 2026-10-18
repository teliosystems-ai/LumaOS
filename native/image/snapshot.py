#!/usr/bin/env python3
"""Capture bounded native build inputs before runtime/package construction.

This is a source snapshot, not a signature or a reproducible-build assertion.
Failed captures remain available for diagnosis and are never reused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

FOLDERS = ('rust', 'native/image', 'native/desktop', 'native/utc', 'src', 'web', 'schemas', 'examples', 'docs/adr', 'scripts')
EXCLUDED = {'target', '__pycache__', '.git'}
MAX_FILE = 16*1024*1024
MAX_TOTAL = 64*1024*1024
MAX_FILES = 4096


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def source_folders(include_tests=False, include_windows=False):
    return (FOLDERS + (('native/tests',) if include_tests else ())
            + (('packaging/windows',) if include_windows else ()))


def inventory(repository, include_tests=False, include_windows=False):
    files = {}
    def visit(path):
        relative = path.relative_to(repository).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            for child in sorted(path.iterdir()):
                if child.name not in EXCLUDED:
                    visit(child)
        elif stat.S_ISREG(metadata.st_mode):
            if path.suffix in ('.pyc', '.pyo'):
                return
            if metadata.st_size > MAX_FILE or len(files) >= MAX_FILES:
                raise ValueError('source inventory exceeds file bounds')
            files[relative] = identity(metadata)
        else:
            raise ValueError('source snapshot refuses links and special files: '+relative)
    folders = source_folders(include_tests, include_windows)
    for name in folders:
        path = repository/name
        for parent in (path, *path.parents):
            if parent == repository:
                break
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ValueError('source root must be a real directory: '+str(parent))
        visit(path)
    visit(repository/'LICENSE')
    if sum(value[3] for value in files.values()) > MAX_TOTAL:
        raise ValueError('source inventory exceeds total bound')
    return files


def capture(repository, output, include_tests=False, include_windows=False):
    repository = repository.resolve(strict=True)
    if output.is_symlink() or output.exists():
        raise ValueError('source snapshot destination must be new')
    output = output.resolve()
    folders = source_folders(include_tests, include_windows)
    for name in folders:
        if output.is_relative_to(repository/name):
            raise ValueError('snapshot output cannot be inside a captured source tree')
    before = inventory(repository, include_tests=include_tests, include_windows=include_windows)
    output.mkdir(parents=True, mode=0o700)
    records = []
    for relative, expected in sorted(before.items()):
        source = repository/relative
        target = output/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream, target.open('xb') as destination:
            if identity(os.fstat(stream.fileno())) != expected:
                raise ValueError('source changed before capture: '+relative)
            digest = hashlib.sha256()
            total = 0
            while block := stream.read(1024*1024):
                total += len(block)
                if total > expected[3]:
                    raise ValueError('source grew during capture: '+relative)
                digest.update(block)
                destination.write(block)
            if total != expected[3] or identity(os.fstat(stream.fileno())) != expected:
                raise ValueError('source changed during capture: '+relative)
        # Later build containers receive this directory read-only. Preserve the
        # executable bit, not writable or special permission bits.
        target.chmod(0o555 if expected[2] & 0o111 else 0o444)
        records.append({'path':relative, 'bytes':total, 'sha256':digest.hexdigest()})
    if inventory(repository, include_tests=include_tests, include_windows=include_windows) != before:
        raise ValueError('source inventory changed during capture')
    manifest = {'schema_version':1, 'files':records}
    with (output/'build-inputs.json').open('x') as stream:
        json.dump(manifest, stream, sort_keys=True, indent=2)
        stream.write('\n')
    (output/'build-inputs.json').chmod(0o444)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include-tests', action='store_true',
                        help='capture native fixtures and the offline development sweep')
    parser.add_argument('--include-windows', action='store_true',
                        help='also bind Windows packaging sources for cross-platform development evidence')
    args = parser.parse_args()
    manifest = capture(args.repository, args.output, include_tests=args.include_tests,
                       include_windows=args.include_windows)
    print(f"Captured {len(manifest['files'])} source files at {args.output}", flush=True)


if __name__ == '__main__':
    main()
