#!/usr/bin/env python3
"""Create inert canonical C99-subset build/test input; never compile or execute."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def protected_module(name, filename):
    path = Path('/usr/libexec/luma-os') / filename
    for entry in (path, *path.parents):
        info = entry.lstat()
        if entry.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('mutable installed request helper')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--tests', type=Path, required=True,
                        help='closed JSON array: stdin_hex, expected_exit, expected_stdout_hex, expected_stderr_hex; one or two tests')
    args = parser.parse_args()
    snapshot = protected_module('luma_request_snapshot', 'prepare_generated_request.py')
    build = protected_module('luma_build_request_contract', 'generated_build.py')
    runtime = build.load_runtime()
    source = snapshot.snapshot(args.source, 16384)
    tests = runtime.closed_json(snapshot.snapshot(args.tests, 32768))
    value = {'schema_version': 2, 'language': build.LANGUAGE,
             'declared_dependencies': build.DEPENDENCIES, 'source_hex': source.hex(), 'tests': tests}
    build.validate_request(value)
    encoded = json.dumps(value, separators=(',', ':')).encode()
    build.parse_request(encoded, runtime)
    sys.stdout.buffer.write(encoded)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('luma-prepare-generated-build: invalid or changed inert input\n')
        raise SystemExit(1)
