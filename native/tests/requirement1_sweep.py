#!/usr/bin/env python3
"""Bounded offline Requirement #1 development sweep in an isolated container.

This executes unit and source/packaging tests, not installed-image qualification.
The caller supplies a read-only source snapshot and separate ext4 storage and
temporary mounts. No host service, clock, account, disk or TPM is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-filter', help='explicit targeted post-sweep regression filter')
    parser.add_argument('--deny-warnings', action='store_true')
    parser.add_argument('--pam-fixture', action='store_true',
                        help='also run the real PAM fixture in this disposable container')
    args = parser.parse_args()
    if args.rust_filter and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]{0,127}', args.rust_filter):
        raise SystemExit('invalid explicit Rust regression filter')
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0:
        raise SystemExit('requires a disposable root tools container')
    if Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists():
        raise SystemExit('physical TPM devices must not be attached')
    repository = args.repository.resolve(strict=True)
    manifest = repository / 'build-inputs.json'
    if manifest.is_symlink() or manifest.stat().st_size > 1024 * 1024:
        raise SystemExit('source manifest exceeds its bound or is linked')
    inputs = json.loads(manifest.read_text())
    if inputs.get('schema_version') != 1 or not inputs.get('files') \
            or len(inputs['files']) > 4096:
        raise SystemExit('requires a bounded immutable source snapshot manifest')
    members = set()
    total = 0
    for record in inputs['files']:
        relative = Path(record['path'])
        if relative.is_absolute() or '..' in relative.parts or not relative.parts \
                or record['path'] in members or relative.as_posix() != record['path'] \
                or not isinstance(record['bytes'], int) or isinstance(record['bytes'], bool) \
                or not 0 <= record['bytes'] <= 16 * 1024 * 1024:
            raise SystemExit('invalid source snapshot member')
        members.add(record['path'])
        total += record['bytes']
        if total > 64 * 1024 * 1024:
            raise SystemExit('source snapshot exceeds total byte bound')
        path = repository / relative
        for parent in path.parents:
            if parent == repository:
                break
            if parent.is_symlink() or not parent.is_dir():
                raise SystemExit('source snapshot contains a redirected ancestor')
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record['bytes'] \
                or digest(path) != record['sha256']:
            raise SystemExit('source snapshot failed byte verification')
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit('evidence directory must be new')
    args.output.mkdir(mode=0o700, parents=True)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', CARGO_INCREMENTAL='0')
    if args.deny_warnings:
        environment['RUSTFLAGS'] = '-Dwarnings'
    results = []
    rust_command = ['cargo', 'test', '--offline', '--locked', '--target-dir', '/cache/target']
    if args.rust_filter:
        rust_command.append(args.rust_filter)
    rust_command.extend(['--', '--test-threads=1'])
    cases = [
        ('rust-all-targets-check', ['cargo', 'check', '--offline', '--locked',
                                  '--all-targets', '--target-dir', '/cache/target'],
                                 repository / 'rust', 600),
        ('rust-tests', rust_command, repository / 'rust', 1800),
        ('native-source-tests', ['/usr/bin/python3', '-B', '-m', 'unittest', 'discover',
                                 '-s', 'native/tests', '-p', 'test_*.py', '-v'], repository, 600),
    ]
    if args.pam_fixture:
        environment['CARGO_TARGET_DIR'] = '/cache/target'
        cases.append(('real-pam-fixture', ['/usr/bin/python3', '-B',
                      str(repository / 'native/tests/principal_pam_integration.py')],
                      repository / 'rust', 600))
    started = time.monotonic()
    for name, command, directory, timeout in cases:
        log = args.output / (name + '.log')
        began = time.monotonic()
        print('Requirement #1 sweep: ' + name, flush=True)
        with log.open('xb') as stream:
            try:
                process = subprocess.Popen(command, cwd=directory, env=environment,
                                           stdout=stream, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                process.wait(timeout=timeout)
                outcome = {'exit_code': process.returncode, 'timed_out': False}
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                outcome = {'exit_code': None, 'timed_out': True}
        results.append(dict(name=name, command=command, elapsed_seconds=round(time.monotonic()-began, 3),
                            transcript_sha256=digest(log), **outcome))
        print(json.dumps(results[-1], sort_keys=True), flush=True)
    record = {'schema_version': 1,
              'scope': 'requirement-1-offline-targeted' if args.rust_filter
                       else 'requirement-1-offline-development',
              'rust_filter': args.rust_filter, 'warnings_denied': args.deny_warnings,
              'real_pam_fixture_requested': args.pam_fixture,
              'result': 'passed' if all(item['exit_code'] == 0 for item in results) else 'failed',
              'kernel': platform.release(), 'source_manifest_sha256': digest(manifest),
              'runner_sha256': digest(Path(__file__)), 'cases': results,
              'elapsed_seconds': round(time.monotonic()-started, 3),
              'physical_tpm_tested': False, 'installed_image_tested': False,
              'production_authorization_qualified': False, 'gate_closing': False}
    with (args.output / 'result.json').open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(record, sort_keys=True), flush=True)
    raise SystemExit(0 if record['result'] == 'passed' else 1)


if __name__ == '__main__':
    main()
