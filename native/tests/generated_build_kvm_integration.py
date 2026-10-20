#!/usr/bin/env python3
"""Actual bounded source compilation/testing in offline disposable KVM guests.

No host/compiler execution of the request source; no AppArmor/installed image
qualification claim. The container must expose only approved /dev/kvm.
"""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

ASSETS = Path(__file__).resolve().parents[1] / 'image/generated'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def request(build, source, stdout=b'', code=0, count=1):
    return {'schema_version': 2, 'language': build.LANGUAGE,
            'declared_dependencies': build.DEPENDENCIES, 'source_hex': source.hex(),
            'tests': [{'stdin_hex': b'hello'.hex(), 'expected_exit': code,
                       'expected_stdout_hex': stdout.hex(), 'expected_stderr_hex': ''} for _ in range(count)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--diagnostic', action='store_true', help='deny syscall with trusted SIGSYS diagnostic; never production qualification')
    args = parser.parse_args()
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0 or {p.name for p in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('requires fresh offline root container')
    if any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/dev/dri', '/var/run/docker.sock')):
        raise ValueError('unexpected hardware or host socket')
    cgroup = {name: (Path('/sys/fs/cgroup') / name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    if cgroup != {'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '16', 'cpu.max': '200000 100000'}:
        raise ValueError('actual compiler diagnostic cgroup differs from approved resource ceiling')
    device = os.stat('/dev/kvm', follow_symlinks=False)
    if not stat.S_ISCHR(device.st_mode) or (os.major(device.st_rdev), os.minor(device.st_rdev)) != (10, 232) or device.st_uid != 0 or device.st_mode & 0o777 != 0o660:
        raise ValueError('requires exact root mode0660 KVM device')
    try:
        group = grp.getgrnam('kvm')
    except KeyError:
        subprocess.run(['groupadd', '--gid', str(device.st_gid), 'kvm'], check=True)
    else:
        if group.gr_gid != device.st_gid:
            subprocess.run(['groupmod', '--gid', str(device.st_gid), 'kvm'], check=True)
    args.output.mkdir(mode=0o700)
    package = module('fixed_generated_packager', ASSETS / 'package_runtime.py')
    source_names = ('compiler_init.c', 'freestanding_runtime.c', 'generated_build.py', 'generated_runtime.py',
                    'guest_init.c', 'luma.h', 'package_build.py', 'package_runtime.py',
                    'prepare_build_request.py', 'prepare_request.py')
    captured_sources = {name: package.source(ASSETS / name, 128*1024) for name in source_names}
    fixture_source = Path(__file__).read_bytes()
    source_unit = args.output / 'source'
    source_unit.mkdir(mode=0o700)
    for name, content in captured_sources.items():
        (source_unit / name).write_bytes(content)
    (source_unit / Path(__file__).name).write_bytes(fixture_source)
    if args.diagnostic:
        original_run = subprocess.run
        def diagnostic_build(command, *values, **options):
            if command[0] == '/usr/bin/cc' and '-c' in command and any(str(value).endswith('/compiler-init.c') for value in command):
                command = [*command, '-DLUMA_COMPILER_DIAGNOSTIC=1']
            return original_run(command, *values, **options)
        subprocess.run = diagnostic_build
    package.package(Path('/'), args.kernel, args.output)
    build = module('fixed_generated_build', Path('/usr/libexec/luma-os/generated_build.py'))
    runtime = build.load_runtime()
    original_command = runtime.qemu_command
    def diagnostic_command(kernel_fd, initrd_fd):
        command = original_command(kernel_fd, initrd_fd)
        command[-1] = command[-1].replace('quiet loglevel=0', 'loglevel=4')
        return command
    if args.diagnostic:
        runtime.qemu_command = diagnostic_command
    original_vm = build.run_vm
    consoles = []
    def recorded_vm(*values):
        raw = original_vm(*values)
        name = 'guest-' + str(len(consoles)) + '.console'
        (args.output / name).write_bytes(raw)
        consoles.append(name)
        return raw
    build.run_vm = recorded_vm
    cases = [
        ('actual-compile-two-tests', b'#include "luma.h"\nint main(void){char b[5];long n=luma_read(b,5);if(n!=5)return 2;return luma_write(b,5)==5?0:3;}\n', b'hello', True, 2),
        ('actual-compile-failure', b'int main(void){ this is not C; }\n', b'', False, 1),
        ('actual-test-failure', b'int main(void){return 4;}\n', b'', False, 1),
        ('actual-test-timeout', b'int main(void){for(;;){}return 0;}\n', b'', False, 1),
        ('actual-test-output-limit', b'#include "luma.h"\nint main(void){char b[512];for(int i=0;i<512;i++)b[i]=65;for(;;)luma_write(b,512);return 0;}\n', b'', False, 1),
        ('actual-test-buffered-output-exit', b'#include "luma.h"\nint main(void){char b[4096];for(int i=0;i<4096;i++)b[i]=65;luma_write(b,4096);return 0;}\n', b'A'*2048, False, 1),
    ]
    results = []
    for name, source, expected, passed, count in cases:
        encoded = request(build, source, expected, count=count)
        started = time.monotonic()
        result = build.run(encoded, runtime)
        elapsed = time.monotonic() - started
        (args.output / (name + '.json')).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        if result['all_tests_passed'] != passed:
            raise ValueError('actual compile/test outcome mismatch: ' + name)
        if name == 'actual-compile-two-tests' and (result['artifact_status'] != 'validated_static_amd64' or len(result['tests']) != 2):
            raise ValueError('real two-test successful build missing')
        if name == 'actual-compile-failure' and (result['compiler']['status'] != 'exit' or result['compiler']['value'] == 0 or result['tests'][0]['status'] != 'not_run'):
            raise ValueError('real compiler failure not preserved')
        if name == 'actual-test-failure' and result['tests'][0].get('execution_value') != 4:
            raise ValueError('real failing exit not preserved')
        if name == 'actual-test-timeout' and result['tests'][0].get('execution_status') not in ('timeout', 'signal'):
            raise ValueError('real timeout/signal not preserved')
        if name == 'actual-test-output-limit' and result['tests'][0].get('execution_status') != 'output_limit':
            raise ValueError('real output exhaustion not preserved')
        results.append({'name': name, 'elapsed_seconds': elapsed, 'all_tests_passed': passed,
                        'receipt_sha256': hashlib.sha256((args.output / (name + '.json')).read_bytes()).hexdigest()})
    if any(package.source(ASSETS / name, 128*1024) != data for name, data in captured_sources.items()) or Path(__file__).read_bytes() != fixture_source:
        raise ValueError('source changed during integrated KVM fixture')
    shutil.copytree(runtime.BASE, args.output / 'appliance')
    proof = {'result': 'passed', 'cases': results, 'kernel_sha256': hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
             'observed_cgroup_limits': cgroup,
             'observed_cgroup_memory_peak': (Path('/sys/fs/cgroup') / 'memory.peak').read_text().strip(),
             'guest_memory_mib': 128, 'worker_deadline_seconds': 20,
             'production_compiler_kill_filter': not args.diagnostic,
             'production_qemu_flags': not args.diagnostic,
             'runtime_manifest_sha256': hashlib.sha256((runtime.BASE / 'manifest.json').read_bytes()).hexdigest(),
             'build_manifest_sha256': hashlib.sha256((runtime.BASE / 'build-manifest.json').read_bytes()).hexdigest(),
             'source_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_unit.iterdir()},
             'installed_authority_qualified': False, 'host_apparmor_qualified': False,
             'production_qualified': False}
    (args.output / 'verification.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
