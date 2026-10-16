#!/usr/bin/env python3
"""Capture the fixed minimal profile-W development userland, without execution.

Use inside the independently pinned offline Ubuntu tools container. WorkRoot is
an explicit caller-supplied D-backed mount, not an inferred host filesystem.
The fixed selection is intentionally not a complete Windows product deployment.
No host accounts, passwords, machine identity, network settings or keys are
copied. The generated root account is locked; it is not a Luma Admin identity.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat

SPEC = importlib.util.spec_from_file_location('luma_windows_package', Path(__file__).with_name('windows_package.py'))
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)

MAX_FILES = 256
MAX_TOTAL = 256 * 1024**2
MAX_CONFIG = 1024**2
PROFILE = 'luma-profile-w-minimal-structural-v1'
BINARIES = (
    'bin/sh', 'usr/bin/bash', 'usr/bin/env', 'usr/bin/cat', 'usr/bin/ls',
    'usr/bin/id', 'usr/bin/uname', 'usr/bin/mkdir', 'usr/bin/rm', 'usr/bin/sleep',
    'usr/bin/true', 'usr/bin/false', 'usr/bin/stat', 'usr/bin/readlink',
    'usr/bin/systemctl', 'usr/bin/systemd-tmpfiles', 'usr/bin/systemd-sysusers',
    'usr/lib/systemd/systemd', 'usr/lib/systemd/systemd-journald',
    'usr/lib/systemd/systemd-remount-fs', 'usr/lib/systemd/systemd-random-seed',
)
UNITS = (
    'basic.target', 'sysinit.target', 'multi-user.target', 'sockets.target',
    'timers.target', 'paths.target', 'slices.target', 'local-fs.target',
    'local-fs-pre.target', 'swap.target', 'shutdown.target', 'umount.target',
    'final.target', 'reboot.target', 'poweroff.target', 'halt.target', 'exit.target',
    'systemd-journald.service', 'systemd-journald.socket', 'systemd-journald-dev-log.socket',
    'systemd-tmpfiles-setup.service', 'systemd-tmpfiles-setup-dev.service',
    'systemd-tmpfiles-setup-dev-early.service', 'systemd-sysusers.service',
    'systemd-remount-fs.service', 'systemd-random-seed.service',
)
CONFIGS = ('etc/os-release', 'etc/ld.so.conf', 'etc/inputrc',
           'etc/ssl/certs/ca-certificates.crt', 'usr/share/zoneinfo/Etc/UTC')
GENERATED = {
    'etc/passwd': (b'root:x:0:0:Development root:/root:/bin/bash\n', 0o644),
    'etc/shadow': (b'root:!:0:0:99999:7:::\n', 0o600),
    'etc/group': (b'root:x:0:\n', 0o644),
    'etc/gshadow': (b'root:!::\n', 0o600),
    'etc/nsswitch.conf': (b'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n', 0o644),
    'etc/hostname': (b'luma-wsl-dev\n', 0o644),
    'etc/machine-id': (b'', 0o444),
    'etc/fstab': (b'# No native disks or Windows folders are enrolled by this development package.\n', 0o644),
}
ALIASES = {'bin/bash': 'usr/bin/bash', 'usr/bin/sh': 'bin/sh',
           'sbin/init': 'usr/lib/systemd/systemd',
           'etc/localtime': 'usr/share/zoneinfo/Etc/UTC',
           'usr/lib/systemd/system/default.target': 'usr/lib/systemd/system/multi-user.target'}


def capture(tree, path, maximum):
    with tree.opened(path) as (descriptor, metadata):
        if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= maximum:
            raise ValueError('stage input is not a bounded regular file: ' + path)
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o7022:
            raise ValueError('stage refuses privileged, sticky or unsafe writable source: ' + path)
        value = bytearray()
        while len(value) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(value)))
            if not block:
                break
            value.extend(block)
        if len(value) != metadata.st_size:
            raise ValueError('stage source changed size during capture')
        return bytes(value), mode, package.identity(metadata)


def stage(root, platform, work_root, output_name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', output_name):
        raise ValueError('stage output name must be one bounded new directory component')
    work_root = Path(os.path.abspath(work_root))
    if work_root == Path('/') or str(work_root).startswith('/mnt/c/') or work_root == Path('/mnt/c'):
        raise ValueError('stage requires an explicit narrow D-backed work mount, not root or C')
    tree = package.Tree(root)
    platform_tree = None
    work = None
    output_fd = None
    root_fd = None
    try:
        identity = tree.read('etc/os-release', 16384).decode('utf-8')
        keys = {}
        for line in identity.splitlines():
            if line.startswith(('ID=', 'VERSION_ID=')):
                matched = re.fullmatch(r'(ID|VERSION_ID)=(?:"([A-Za-z0-9.]+)"|([A-Za-z0-9.]+))', line)
                if not matched or matched[1] in keys:
                    raise ValueError('ambiguous source Ubuntu identity')
                keys[matched[1]] = matched[2] or matched[3]
        if keys != {'ID': 'ubuntu', 'VERSION_ID': '24.04'}:
            raise ValueError('fixed development stage requires Ubuntu 24.04 source userland')
        data, source_metadata, origins = {}, {}, {}
        total = 0
        def add(path, value, mode, origin):
            nonlocal total
            package.archive_path(path)
            if path in data:
                if data[path] != (value, mode):
                    raise ValueError('stage source aliases collide with differing bytes or modes')
                return
            if len(data) >= MAX_FILES or total + len(value) > MAX_TOTAL:
                raise ValueError('stage exceeds fixed file/byte bound')
            total += len(value)
            data[path] = (value, mode)
            origins[path] = origin
        def source(path, maximum=package.MAX_ELF):
            if path in data:
                return data[path][0]
            value, mode, metadata = capture(tree, path, maximum)
            source_metadata[path] = metadata
            add(path, value, mode, {'kind': 'source-root', 'path': path})
            return value
        for path in CONFIGS:
            source(path, MAX_CONFIG)
        # Only this exact bounded *.conf directory is enumerated, not /etc.
        with tree.opened('etc/ld.so.conf.d', directory=True) as (descriptor, metadata):
            configuration_names = sorted(os.listdir(descriptor))
            if len(configuration_names) > 32:
                raise ValueError('loader configuration directory exceeds fixed bound')
            source_metadata['etc/ld.so.conf.d'] = package.identity(metadata)
            for name in configuration_names:
                if not name.endswith('.conf'):
                    raise ValueError('unsupported loader configuration member')
                source('etc/ld.so.conf.d/' + name, 16384)
        for name in UNITS:
            source('usr/lib/systemd/system/' + name, 65536)
        for path in BINARIES:
            source(path)
        platform_path = Path(os.path.abspath(platform))
        platform_tree = package.Tree(platform_path.parent)
        value, mode, metadata = capture(platform_tree, platform_path.name, package.MAX_ELF)
        package.elf(value, require_entry=True, object_path='usr/bin/luma-platform')
        add('usr/bin/luma-platform', value, 0o755,
            {'kind': 'caller-compiled-platform', 'sha256': hashlib.sha256(value).hexdigest()})
        platform_metadata = metadata
        roots = (*BINARIES, 'usr/bin/luma-platform')
        todo = [(path, (), path) for path in roots]
        loaded = {path: {} for path in roots}
        checked = set()
        while todo:
            path, inherited, scope = todo.pop()
            key = (path, inherited, scope)
            if key in checked:
                continue
            checked.add(key)
            if len(checked) > 4096:
                raise ValueError('staging dependency graph exceeds fixed bound')
            interpreter, needed, search = package.elf(data[path][0], object_path=path,
                require_entry=path in BINARIES or path == 'usr/bin/luma-platform', details=True)
            next_inherited = tuple(dict.fromkeys((*search['rpath'], *inherited)))
            private = search['runpath'] if search['runpath'] is not None else next_inherited
            folders = tuple(dict.fromkeys((*private, *package.LIB_DIRS)))
            dependencies = [interpreter[1:]] if interpreter else []
            for name in needed:
                candidates = []
                for folder in folders:
                    candidate = folder + '/' + name
                    try:
                        value = source(candidate)
                    except FileNotFoundError:
                        continue
                    candidates.append((candidate, hashlib.sha256(value).digest()))
                existing = loaded[scope].get(name)
                if existing is not None and not any(candidate == existing for candidate, _ in candidates):
                    candidates.append((existing, hashlib.sha256(data[existing][0]).digest()))
                if not candidates:
                    raise ValueError('stage cannot resolve real ELF dependency: ' + name + ' for ' + path)
                if len({digest for _, digest in candidates}) != 1:
                    raise ValueError('stage refuses ambiguous soname bytes: ' + name)
                selected = existing if existing is not None else candidates[0][0]
                _, _, selected_metadata = package.elf(data[selected][0], object_path=selected, details=True)
                if selected_metadata['soname'] not in (None, name):
                    raise ValueError('stage dependency SONAME differs from requested name: ' + name)
                loaded[scope][name] = selected
                dependencies.append(selected)
            for dependency in dependencies:
                source(dependency)
                todo.append((dependency, next_inherited, scope))
        for path, original in ALIASES.items():
            value, mode = data[original]
            add(path, value, mode, {'kind': 'explicit-flattened-alias', 'path': original})
        for path, (value, mode) in GENERATED.items():
            add(path, value, mode, {'kind': 'fixed-locked-development-profile', 'profile': PROFILE})
        # Recheck every captured source object, not just the source root inode.
        for path, expected in source_metadata.items():
            with tree.opened(path) as (_, metadata):
                if package.identity(metadata) != expected:
                    raise ValueError('stage source changed after capture: ' + path)
        with platform_tree.opened(platform_path.name) as (_, metadata):
            if package.identity(metadata) != platform_metadata:
                raise ValueError('compiled platform input changed after capture')
        work = package.Tree(work_root)
        os.mkdir(output_name, mode=0o700, dir_fd=work.fd)
        output_fd = os.open(output_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=work.fd)
        os.mkdir('rootfs', mode=0o755, dir_fd=output_fd)
        root_fd = os.open('rootfs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=output_fd)
        def directory(path, mode=0o755):
            parent = os.dup(root_fd)
            try:
                for index, part in enumerate(path.split('/')):
                    try:
                        os.mkdir(part, mode=mode if index == len(path.split('/')) - 1 else 0o755, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                os.fchmod(parent, mode)
            finally:
                os.close(parent)
        def write(path, value, mode):
            pieces = path.split('/')
            if len(pieces) > 1:
                directory('/'.join(pieces[:-1]))
            parent = os.dup(root_fd)
            try:
                for part in pieces[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                with os.fdopen(os.open(pieces[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                       mode, dir_fd=parent), 'wb') as stream:
                    stream.write(value)
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchmod(stream.fileno(), mode)
            finally:
                os.close(parent)
        records = []
        for path, (value, mode) in sorted(data.items()):
            write(path, value, mode)
            records.append({'path': path, 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                            'mode': mode, 'origin': origins[path]})
        for path in ('dev', 'proc', 'sys', 'run', 'home', 'var/lib', 'var/log', 'etc/systemd/system'):
            directory(path)
        directory('root', 0o700)
        directory('tmp', 0o1777)
        directory('var/tmp', 0o1777)
        plan = {'schema_version': 1, 'exclude_paths': [], 'normalize_privileged_modes': False}
        report = {'schema_version': 1, 'profile': PROFILE, 'status': 'real-minimal-userland-staged-not-product-qualified',
                  'file_count': len(records), 'content_bytes': total, 'files': records,
                  'accounts_copied_from_source': False, 'host_keys_copied': False,
                  'host_machine_id_copied': False, 'host_resolver_copied': False,
                  'development_root_account_locked': True, 'luma_admin_provisioned': False,
                  'actual_elf_inputs_captured': True, 'source_authentication_established': False,
                  'source_image_pin_required_independently': True, 'work_mount_backing_qualified': False,
                  'elf_needed_closure_checked': True, 'dlopen_dependencies_qualified': False,
                  'systemd_unit_dependency_closure_qualified': False, 'boot_configuration_qualified': False,
                  'service_enablement_configured': False, 'guest_confinement_qualified': False,
                  'model_runtime_installed': False, 'package_authenticated': False,
                  'product_installation_admitted': False, 'distribution_imported': False,
                  'host_settings_changed': False, 'production_qualified': False, 'gate_closing': False}
        for name, value in (('plan.json', plan), ('stage.json', report)):
            with os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   0o600, dir_fd=output_fd), 'wb') as stream:
                stream.write(package.canonical(value))
                stream.flush()
                os.fsync(stream.fileno())
        return report
    finally:
        if root_fd is not None:
            os.close(root_fd)
        if output_fd is not None:
            os.close(output_fd)
        if work is not None:
            work.close()
        if platform_tree is not None:
            platform_tree.close()
        tree.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--work-root', type=Path, required=True)
    parser.add_argument('--output-name', required=True)
    arguments = parser.parse_args()
    result = stage(arguments.root, arguments.platform, arguments.work_root, arguments.output_name)
    print(package.canonical({key: value for key, value in result.items() if key != 'files'}).decode(), end='')
