#!/usr/bin/env python3
"""Build the fixed guest appliance before verity; no generated code is run."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

ASSETS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('luma_generated_fixed_runner', ASSETS / 'generated_runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def source(path, maximum):
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise ValueError('redirected build input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError('nonregular/linked/oversized build input')
        data = file.read(maximum + 1)
        if len(data) != before.st_size or runtime.identity(before) != runtime.identity(os.fstat(file.fileno())) or runtime.identity(before) != runtime.identity(path.lstat()):
            raise ValueError('build input changed during read')
        return data


def publish(path, data, executable=False):
    if path.exists() or path.is_symlink():
        raise ValueError('generated appliance destinations must be new')
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise ValueError('redirected appliance output')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o755 if executable else 0o444)
    with os.fdopen(descriptor, 'w+b') as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
        file.seek(0)
        if file.read(len(data) + 1) != data:
            raise ValueError('appliance publication readback mismatch')


def package(root, kernel, work):
    root, kernel, work = Path(root), Path(kernel), Path(work)
    if root.is_symlink() or work.is_symlink() or not root.is_dir() or not work.is_dir():
        raise ValueError('requires actual image root and isolated build work directory')
    target = root / 'usr/share/luma-os/generated'
    if target.exists() or target.is_symlink():
        raise ValueError('generated appliance cannot replace existing image inputs')
    unit = work / 'generated-runtime'
    unit.mkdir(mode=0o700)
    init_source = source(ASSETS / 'guest_init.c', 128 * 1024)
    runner = source(ASSETS / 'generated_runtime.py', 128 * 1024)
    request_helper = source(ASSETS / 'prepare_request.py', 128 * 1024)
    kernel_bytes = source(kernel, 32 * 1024 * 1024)
    qemu = source(root / 'usr/bin/qemu-system-x86_64', 128 * 1024 * 1024)
    if not kernel_bytes or not qemu.startswith(b'\x7fELF'):
        raise ValueError('actual kernel/QEMU image inputs are missing')
    publish(unit / 'guest-init.c', init_source)
    command = ['/usr/bin/cc', '-O2', '-static', '-s', '-fno-pie', '-no-pie', '-Wall', '-Wextra',
               '-Werror', '-Wl,-z,noexecstack', str(unit / 'guest-init.c'), '-o', str(unit / 'guest-init')]
    with (unit / 'build.log').open('xb') as transcript:
        result = subprocess.run(command, stdout=transcript, stderr=subprocess.STDOUT,
                                env={'PATH': '/usr/bin', 'LC_ALL': 'C'}, timeout=60)
    if result.returncode:
        raise ValueError('fixed guest init compilation failed; build transcript retained')
    init = source(unit / 'guest-init', 1048576)
    runtime.validate_static_elf(init)
    initrd = runtime.cpio([('init', init, stat.S_IFREG | 0o755, 0, 0, 0, 0),
                           ('dev', b'', stat.S_IFDIR | 0o755, 0, 0, 0, 0),
                           ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1)])
    manifest = {'schema_version': 1, **runtime.CONTRACT,
                'kernel_sha256': hashlib.sha256(kernel_bytes).hexdigest(),
                'base_initrd_sha256': hashlib.sha256(initrd).hexdigest(),
                'qemu_sha256': hashlib.sha256(qemu).hexdigest(),
                'guest_init_sha256': hashlib.sha256(init).hexdigest(),
                'guest_init_source_sha256': hashlib.sha256(init_source).hexdigest(),
                'runner_sha256': hashlib.sha256(runner).hexdigest()}
    publish(target / 'kernel', kernel_bytes)
    publish(target / 'base-initrd.cpio', initrd)
    publish(target / 'guest-init', init)
    publish(target / 'guest-init.c', init_source)
    publish(root / 'usr/libexec/luma-os/generated_runtime.py', runner, executable=True)
    publish(root / 'usr/libexec/luma-os/prepare_generated_request.py', request_helper, executable=True)
    publish(target / 'manifest.json', (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.root, args.kernel, args.work), sort_keys=True))
