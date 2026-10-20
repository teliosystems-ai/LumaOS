#!/usr/bin/env python3
"""Build immutable libtcc guest and its relinkable LGPL distribution kit."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess

ASSETS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('luma_build_contract_packaging', ASSETS / 'generated_build.py')
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def package(root, work, old_manifest, source, publish, runtime):
    target = root / 'usr/share/luma-os/generated'
    unit = work / 'generated-compiler'
    unit.mkdir(mode=0o700)
    paths = {
        'libtcc1.a': root / 'usr/lib/x86_64-linux-gnu/tcc/libtcc1.a',
        'relink/libtcc.a': root / 'usr/lib/x86_64-linux-gnu/libtcc.a',
        'relink/libtcc.h': root / 'usr/include/libtcc.h',
        'relink/copyright': root / 'usr/share/doc/tcc/copyright',
        'compiler-init.c': ASSETS / 'compiler_init.c',
        'luma.h': ASSETS / 'luma.h',
        'freestanding_runtime.c': ASSETS / 'freestanding_runtime.c',
        'relink/guest_init.c': ASSETS / 'guest_init.c',
        'build-runner.py': ASSETS / 'generated_build.py',
        'prepare-build.py': ASSETS / 'prepare_build_request.py'}
    for filename in build.SOURCE_FILES:
        paths['relink/source/' + filename] = root / 'usr/src/luma-tcc' / filename
    for license_name in ('LGPL-2', 'LGPL-2.1', 'GPL-2'):
        paths['relink/' + license_name] = root / 'usr/share/common-licenses' / license_name
    files = {name: source(path, build.FILE_NAMES[name]) for name, path in paths.items()}
    if any(hashlib.sha256(files[name]).hexdigest() != digest for name, digest in build.PINNED_TOOLCHAIN.items()):
        raise ValueError('compiler package files differ from exact reviewed package extraction')
    for filename, (maximum, digest) in build.SOURCE_FILES.items():
        actual = files['relink/source/' + filename]
        if len(actual) != maximum or hashlib.sha256(actual).hexdigest() != digest:
            raise ValueError('corresponding compiler source differs from signed snapshot pin')
    files['relink/source-provenance.json'] = (json.dumps({
        'schema_version': 1, 'source_package': 'tcc', 'version': build.VERSION,
        'archive': 'https://snapshot.ubuntu.com/ubuntu/20260927T000000Z/',
        'distribution': 'noble', 'component': 'universe',
        'signed_metadata': 'dists/noble/InRelease -> universe/source/Sources -> pool/universe/t/tcc/',
        'files': {name: {'bytes': size, 'sha256': digest} for name, (size, digest) in build.SOURCE_FILES.items()}},
        sort_keys=True, separators=(',', ':')) + '\n').encode()
    result = subprocess.run(['/usr/bin/dpkg-query', '--admindir=' + str(root / 'var/lib/dpkg'),
                             '-W', '-f=${binary:Package} ${Version}\n', 'tcc', 'libtcc-dev'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
    if set(result.stdout.decode('ascii').splitlines()) != {'tcc ' + build.VERSION, 'libtcc-dev:amd64 ' + build.VERSION}:
        raise ValueError('image compiler packages differ from pinned supported toolchain')
    for name in ('compiler-init.c', 'relink/libtcc.a', 'relink/libtcc.h', 'relink/guest_init.c'):
        publish(unit / name, files[name])
    # Only trusted fixed appliance code is compiled here. All request source
    # enters the KVM compiler later, after its deny-exec seccomp installation.
    common = ['/usr/bin/cc', '-O2', '-fno-pie', '-Wall', '-Wextra', '-Werror']
    commands = [
        common + ['-I' + str(unit / 'relink'), '-c', str(unit / 'compiler-init.c'), '-o', str(unit / 'compiler-init.o')],
        ['/usr/bin/cc', '-static', '-no-pie', '-Wl,-z,noexecstack', str(unit / 'compiler-init.o'),
         str(unit / 'relink/libtcc.a'), '-lm', '-ldl', '-o', str(unit / 'compiler-init')],
        common + ['-static', '-no-pie', '-DOUTPUT_MAX=2048', '-DWALL_MS=1000', '-DREPORT_LIMITS=1',
                  '-Wl,-z,noexecstack', str(unit / 'relink/guest_init.c'), '-o', str(unit / 'test-init')]]
    with (unit / 'build.log').open('xb') as log:
        for command in commands:
            if subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                              env={'PATH': '/usr/bin', 'LC_ALL': 'C'}, timeout=60).returncode:
                raise ValueError('trusted compiler appliance build failed; transcript retained')
    for name, filename in [('compiler-init', 'compiler-init'), ('test-init', 'test-init'),
                           ('relink/compiler-init.o', 'compiler-init.o')]:
        files[name] = source(unit / filename, build.FILE_NAMES[name])
    runtime.validate_static_elf(files['compiler-init'], trusted_appliance=True)
    runtime.validate_static_elf(files['test-init'])
    files['relink/relink.sh'] = b'''#!/bin/sh
set -eu
# Run in generated/relink on amd64 GNU/Linux with a C compiler and static
# libc/libm development libraries. A modified LGPL TinyCC archive may replace
# libtcc.a. compiler-init.o is the entire fixed application, not library code.
cc -static -no-pie -Wl,-z,noexecstack compiler-init.o libtcc.a -lm -ldl -o compiler-init-relinked
'''
    files['compiler-base.cpio'] = runtime.cpio([
        ('init', files['compiler-init'], stat.S_IFREG | 0o755, 0, 0, 0, 0),
        ('dev', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1),
        ('work', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('compiler', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('compiler/libtcc1.a', files['libtcc1.a'], stat.S_IFREG | 0o444, 0, 0, 0, 0),
        ('include', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('include/luma.h', files['luma.h'], stat.S_IFREG | 0o444, 0, 0, 0, 0),
        ('runtime.c', files['freestanding_runtime.c'], stat.S_IFREG | 0o444, 0, 0, 0, 0)])
    files['test-base.cpio'] = runtime.cpio([
        ('init', files['test-init'], stat.S_IFREG | 0o755, 0, 0, 0, 0),
        ('dev', b'', stat.S_IFDIR | 0o755, 0, 0, 0, 0),
        ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1)])
    if set(files) != set(build.FILE_NAMES) or any(len(data) > build.FILE_NAMES[name] for name, data in files.items()):
        raise ValueError('unsupported compiler appliance closure size')
    for name, data in files.items():
        publish(target / name, data, executable=name == 'relink/relink.sh')
    publish(root / 'usr/libexec/luma-os/generated_build.py', files['build-runner.py'], executable=True)
    publish(root / 'usr/libexec/luma-os/prepare_generated_build.py', files['prepare-build.py'], executable=True)
    manifest = {**build.CONTRACT, 'runtime_manifest_sha256': hashlib.sha256(old_manifest).hexdigest(),
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    publish(target / 'build-manifest.json', (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return manifest
