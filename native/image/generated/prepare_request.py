#!/usr/bin/env python3
"""Prepare data for a governed generated-code request; never run or compile it.

The separate governed executor chooses its immutable kernel, resources and
finite authority. This tool grants none of those things.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ASSETS = Path(__file__).absolute().parent
SPEC = importlib.util.spec_from_file_location('luma_generated_request_validator',
                                            ASSETS / 'generated_runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
MAX_REQUEST = 2_228_480


def pin(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def snapshot(path, maximum):
    """Capture one stable single-link regular file through no-follow parents."""
    path = Path(os.path.abspath(os.fspath(path)))
    components = path.parts[1:]
    if not components or any(part in ('', '.', '..') for part in components):
        raise ValueError('requires a regular file path')
    descriptors = []
    parents = []
    file = None
    try:
        descriptor = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        parents.append((Path('/'), pin(os.fstat(descriptor))))
        named = Path('/')
        for part in components[:-1]:
            descriptor = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=descriptors[-1])
            descriptors.append(descriptor)
            named = named / part
            parents.append((named, pin(os.fstat(descriptor))))
        file = os.open(components[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=descriptors[-1])
        before = os.fstat(file)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise ValueError('requires bounded unlinked-to-others regular data')
        chunks = []
        total = 0
        while True:
            block = os.read(file, min(32768, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise ValueError('input exceeds its bound')
        data = b''.join(chunks)
        if len(data) != before.st_size or pin(before) != pin(os.fstat(file)) or pin(before) != pin(
                os.stat(components[-1], dir_fd=descriptors[-1], follow_symlinks=False)):
            raise ValueError('input changed during capture')
        for descriptor, (named, expected) in zip(descriptors, parents):
            if expected != pin(os.fstat(descriptor)) or expected != pin(named.lstat()):
                raise ValueError('input namespace changed during capture')
        return data
    finally:
        if file is not None:
            os.close(file)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def prepare(executable, stdin=None):
    elf = snapshot(executable, 1048576)
    runtime.validate_static_elf(elf)
    data = b'' if stdin is None else snapshot(stdin, 65536)
    # Declaration order matches the closed Rust request type, not authority.
    request = {'schema_version': 1, 'executable_hex': elf.hex(), 'stdin_hex': data.hex()}
    result = json.dumps(request, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(result) > MAX_REQUEST:
        raise ValueError('canonical request exceeds its bound')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--stdin-file', type=Path)
    args = parser.parse_args()
    if not sys.platform.startswith('linux'):
        raise ValueError('requires Linux descriptor semantics')
    sys.stdout.buffer.write(prepare(args.executable, args.stdin_file))
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print('Generated request refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
