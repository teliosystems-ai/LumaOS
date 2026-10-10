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


def executed_tests(name, output):
    """An empty or unrecognized test invocation cannot qualify a lane."""
    if name == 'rust-tests' or name.startswith('rust-tests-'):
        summaries = re.findall(
            r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; '
            r'(\d+) ignored; (\d+) measured; (\d+) filtered out;',
            output, re.MULTILINE)
        counts = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                          (sum(int(row[column]) for row in summaries) for column in range(5))))
        if not summaries or counts['passed'] + counts['failed'] == 0:
            raise ValueError('Rust lane did not execute any recognized tests')
        return counts
    if name == 'native-source-tests':
        summaries = re.findall(r'^Ran (\d+) tests? in .+$', output, re.MULTILINE)
        if len(summaries) != 1 or int(summaries[0]) == 0:
            raise ValueError('native lane did not execute a recognized nonempty suite')
        terminal = re.findall(r'^(OK|FAILED)(?: \(([^\n]+)\))?$', output, re.MULTILINE)
        if len(terminal) != 1:
            raise ValueError('native lane lacks an unambiguous terminal summary')
        details = dict((key, int(value)) for key, value in
                       re.findall(r'(skipped|failures|errors|expected failures|unexpected successes)=(\d+)',
                                  terminal[0][1]))
        discovered = int(summaries[0])
        failed = details.get('failures', 0) + details.get('errors', 0)
        skipped = details.get('skipped', 0)
        return {'discovered': discovered, 'passed': discovered - failed - skipped
                - details.get('expected failures', 0) - details.get('unexpected successes', 0),
                'failed': failed, 'skipped': skipped, **details}
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-filter', help='explicit targeted post-sweep regression filter')
    parser.add_argument('--extra-rust-filter', action='append', default=[],
                        help='additional independently executed targeted regression filter')
    parser.add_argument('--deny-warnings', action='store_true')
    parser.add_argument('--pam-fixture', action='store_true',
                        help='also run the real PAM fixture in this disposable container')
    parser.add_argument('--resource-tpm-fixture', action='store_true',
                        help='run four independent resource authority cases on fresh software TPMs')
    parser.add_argument('--admin-tpm-fixture', action='store_true',
                        help='regression-test existing-owner Admin enrollment on a fresh software TPM')
    args = parser.parse_args()
    filters = ([args.rust_filter] if args.rust_filter else []) + args.extra_rust_filter
    if (args.extra_rust_filter and not args.rust_filter) or len(filters) > 8 \
            or len(set(filters)) != len(filters) \
            or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]{0,127}', value)
                   for value in filters):
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
    def rust_command(value):
        command = ['cargo', 'test', '--offline', '--locked', '--target-dir', '/cache/target']
        if value:
            command.append(value)
        return command + ['--', '--test-threads=1']
    cases = [
        ('rust-all-targets-check', ['cargo', 'check', '--offline', '--locked',
                                  '--all-targets', '--target-dir', '/cache/target'],
                                 repository / 'rust', 600),
        ('rust-tests', rust_command(args.rust_filter), repository / 'rust', 1800),
    ]
    cases.extend(('rust-tests-' + value.replace(':', '-'), rust_command(value),
                  repository / 'rust', 1800) for value in args.extra_rust_filter)
    cases.extend([
        ('native-source-tests', ['/usr/bin/python3', '-B', '-m', 'unittest', 'discover',
                                 '-s', 'native/tests', '-p', 'test_*.py', '-v'], repository, 600),
    ])
    if args.pam_fixture:
        environment['CARGO_TARGET_DIR'] = '/cache/target'
        cases.append(('real-pam-fixture', ['/usr/bin/python3', '-B',
                      str(repository / 'native/tests/principal_pam_integration.py')],
                      repository / 'rust', 600))
    if args.resource_tpm_fixture or args.admin_tpm_fixture:
        environment['CARGO_TARGET_DIR'] = '/cache/target'
    if args.resource_tpm_fixture:
        cases.append(('resource-software-tpm', ['/usr/bin/python3', '-B',
                      str(repository / 'native/tests/resource_checkpoint_integration.py')],
                      repository / 'rust/luma-platform', 1500))
    if args.admin_tpm_fixture:
        cases.append(('admin-software-tpm-regression', ['/usr/bin/python3', '-B',
                      str(repository / 'native/tests/admin_enrollment_integration.py')],
                      repository / 'rust', 1500))
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
        counts = None
        verification_error = None
        if outcome['exit_code'] == 0:
            try:
                counts = executed_tests(name, log.read_text(errors='replace'))
            except ValueError as error:
                verification_error = str(error)
        results.append(dict(name=name, command=command, elapsed_seconds=round(time.monotonic()-began, 3),
                            transcript_sha256=digest(log), test_counts=counts,
                            verification_error=verification_error, **outcome))
        print(json.dumps(results[-1], sort_keys=True), flush=True)
    record = {'schema_version': 1,
              'scope': 'requirement-1-offline-targeted' if args.rust_filter
                       else 'requirement-1-offline-development',
              'rust_filter': args.rust_filter, 'warnings_denied': args.deny_warnings,
              'extra_rust_filters': args.extra_rust_filter,
              'real_pam_fixture_requested': args.pam_fixture,
              'resource_software_tpm_requested': args.resource_tpm_fixture,
              'admin_software_tpm_requested': args.admin_tpm_fixture,
              'chrony_fixture': 'release-4.9-pinned' if environment.get('LUMA_CHRONY_RELEASE_UPSTREAM')
                                 else ('commit-pinned' if environment.get('LUMA_CHRONY_UPSTREAM')
                                       else 'not-supplied'),
              'cargo_profile_test_debug': environment.get('CARGO_PROFILE_TEST_DEBUG', 'default'),
              'cargo_profile_dev_debug': environment.get('CARGO_PROFILE_DEV_DEBUG', 'default'),
              'result': 'passed' if all(item['exit_code'] == 0 and item['verification_error'] is None
                                       for item in results) else 'failed',
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
