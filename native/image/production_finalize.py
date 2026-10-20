#!/usr/bin/env python3
"""Continue a frozen production build through external public signature phases.

This never compiles product source, generates a key, signs a byte, admits an
Admin, changes a clock, or claims that native hardware/custody is qualified.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True

FIELDS = {'schema_version', 'identity', 'root_hash', 'kernel',
          'source_lock_sha256', 'initrd_policy', 'desktop'}
IDENTITY = {'schema_version', 'release', 'sequence', 'environment',
            'architecture', 'ubuntu', 'edition'}


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate production assembly field')
        result[name] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def regular(path, maximum):
    path = Path(path)
    parents = []
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('production assembly parent is unprotected or linked')
        parents.append((parent, (info.st_dev, info.st_ino, info.st_mode, info.st_uid)))
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != 0 or before.st_mode & 0o022 or before.st_size > maximum):
        raise ValueError('production assembly file is unsafe or outside its bound')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_uid, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid, opened.st_size,
                opened.st_mtime_ns, opened.st_ctime_ns):
            raise ValueError('production assembly file changed during descriptor capture')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    named = path.lstat()
    if (len(raw) > maximum or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('production assembly file changed while reading')
    if (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_uid, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns) != (
            named.st_dev, named.st_ino, named.st_mode, named.st_nlink, named.st_uid, named.st_size,
            named.st_mtime_ns, named.st_ctime_ns):
        raise ValueError('production assembly named file changed while reading')
    for parent, expected in parents:
        info = parent.lstat()
        if (info.st_dev, info.st_ino, info.st_mode, info.st_uid) != expected:
            raise ValueError('production assembly parent namespace changed while reading')
    return raw


def parse_checkpoint(raw):
    value = document(raw)
    if type(value) is not dict or set(value) != FIELDS or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('unsupported production assembly checkpoint')
    identity = value['identity']
    if (type(identity) is not dict or set(identity) != IDENTITY
            or type(identity['schema_version']) is not int or identity['schema_version'] != 1
            or identity['environment'] != 'production' or identity['architecture'] != 'amd64'
            or identity['ubuntu'] != '24.04' or identity['edition'] not in ('headless', 'desktop')
            or type(identity['sequence']) is not int or not 1 <= identity['sequence'] < 2**63
            or not isinstance(identity['release'], str)
            or re.fullmatch('[A-Za-z0-9._-]{1,64}', identity['release']) is None):
        raise ValueError('production assembly identity is not the closed current profile')
    for field in ('root_hash', 'source_lock_sha256'):
        if not isinstance(value[field], str) or re.fullmatch('[0-9a-f]{64}', value[field]) is None:
            raise ValueError('production assembly checkpoint digest differs')
    if not isinstance(value['kernel'], str) or re.fullmatch('[0-9][A-Za-z0-9.+_-]{0,95}', value['kernel']) is None:
        raise ValueError('production assembly kernel identifier differs')
    desktop = value['desktop']
    expected = ({'profile': 'console', 'wayland_session_tested': False}
                if identity['edition'] == 'headless' else
                {'profile': 'gnome-wayland-v1', 'wayland_session_tested': False,
                 'model_required_for_login': False, 'live_graphical_login': False})
    if desktop != expected:
        raise ValueError('production assembly cannot assert native desktop qualification')
    initrd = value['initrd_policy']
    if (type(initrd) is not dict or set(initrd) != {'phase_module', 'required_paths', 'shutdown'}
            or initrd['phase_module'] != 'luma-pcrphase'
            or type(initrd['required_paths']) is not list
            or type(initrd['shutdown']) is not dict
            or set(initrd['shutdown']) != {'required_paths', 'boot_tested'}
            or initrd['shutdown']['boot_tested'] is not False
            or type(initrd['shutdown']['required_paths']) is not list):
        raise ValueError('production assembly cannot manufacture initrd boot evidence')
    return value


def verify_source(source, lock_raw, expected):
    if hashlib.sha256(lock_raw).hexdigest() != expected:
        raise ValueError('production phase source lock differs from frozen build')
    lock = document(lock_raw)
    if (type(lock) is not dict or set(lock) != {'schema_version', 'files'}
            or type(lock['schema_version']) is not int or lock['schema_version'] != 1
            or type(lock['files']) is not list or not 1 <= len(lock['files']) <= 4096):
        raise ValueError('production phase source inventory is invalid')
    expected_files = {}
    total = 0
    for entry in lock['files']:
        if (type(entry) is not dict or set(entry) != {'path', 'bytes', 'sha256'}
                or type(entry['path']) is not str or Path(entry['path']).as_posix() != entry['path']
                or entry['path'].startswith('/') or '\\' in entry['path']
                or any(p in ('', '.', '..') for p in entry['path'].split('/'))
                or entry['path'] in expected_files or type(entry['bytes']) is not int
                or not 0 <= entry['bytes'] <= 16 * 1024**2
                or not isinstance(entry['sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', entry['sha256']) is None):
            raise ValueError('production phase source entry escapes exact bounded inventory')
        raw = regular(source/entry['path'], entry['bytes'])
        if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError('frozen production phase code bytes changed')
        expected_files[entry['path']] = entry
        total += len(raw)
    if list(expected_files) != sorted(expected_files) or total > 64 * 1024**2:
        raise ValueError('production phase source count/order/bytes exceed bounds')
    actual = set()
    for directory, directories, files in os.walk(source, followlinks=False):
        for name in directories:
            if not stat.S_ISDIR((Path(directory)/name).lstat().st_mode):
                raise ValueError('production phase source contains a linked directory')
        for name in files:
            actual.add((Path(directory)/name).relative_to(source).as_posix())
    if actual != set(expected_files):
        raise ValueError('production phase source has missing or undeclared files, including bytecode')


def frozen_module(source, name):
    spec = importlib.util.spec_from_file_location('luma_production_' + name,
                                                source/'native/image'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def continue_phase(phase, work, response):
    work, response = Path(work), Path(response)
    out, root, source = work/'artifacts', work/'root', work/'source'
    from assembly_storage import require_ext4
    require_ext4(out)
    checkpoint = parse_checkpoint(regular(out/'production-build.json', 65536))
    lock = regular(out/'source-lock.json', 1024**2)
    verify_source(source, lock, checkpoint['source_lock_sha256'])
    identity = document(regular(root/'usr/share/luma-os/release-identity.json', 4096))
    if identity != checkpoint['identity'] or regular(root/'usr/share/luma-os/source-lock.json', 1024**2) != lock:
        raise ValueError('production phase changes immutable identity or source provenance')
    if (out/'build.json').exists() or (out/(identity['release'] + '.img')).exists():
        raise ValueError('production phase refuses an already sealed or partial final image')
    sys.path.insert(0, str(source/'native/image'))
    custody = frozen_module(source, 'production_release')
    if phase == 'pcr':
        return custody.accept_pcr(out, response)
    if phase == 'pe':
        custody.accept_pe(out, response)
        assembly = frozen_module(source, 'assemble')
        names = ['root.ext4', 'root.verity', 'slot-a.efi', 'slot-b.efi', 'bootloader.efi', 'secureboot.cer']
        manifest = {**identity, 'root_hash': checkpoint['root_hash'],
                    'root_bytes': (out/'root.ext4').stat().st_size,
                    'hash_bytes': (out/'root.verity').stat().st_size,
                    'artifacts': [{'name': name, 'bytes': (out/name).stat().st_size,
                                   'sha256': assembly.digest(out/name)} for name in names]}
        return custody.prepare_release(out, json.dumps(manifest, separators=(',', ':')).encode() + b'\n')
    if phase != 'release':
        raise ValueError('unsupported production assembly response phase')
    custody.accept_release(out, response)
    verified = custody.verify_complete(out)
    assembly = frozen_module(source, 'assemble')
    assembly.WORK, assembly.ROOT, assembly.OUT, assembly.REPO = work, root, out, source
    boot = frozen_module(source, 'boot_policy')
    public = out/'production-public/pcr-policy.pub'
    certificate = out/'production-public/secureboot.pem'
    records = [boot.verify_uki(out/f'slot-{slot}.efi', slot, public.read_bytes(), certificate)
               for slot in ('a', 'b', 'live', 'optical')]
    policy = {'schema_version': 1, 'environment': 'production', 'slots': records,
              'initrd': checkpoint['initrd_policy'], 'enrollment_active': False, 'gate_closing': False}
    with (out/'boot-policy.json').open('x') as stream:
        json.dump(policy, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    manifest = document(regular(out/'release.json', 65536))
    assembly.seal_media(manifest, checkpoint['desktop'], checkpoint['kernel'])
    return {'schema_version': 1, 'phase': 'sealed-production-media',
            'signature_verification': verified, 'native_qualification_claimed': False,
            'custody_qualified': False, 'gate_closing': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('pcr', 'pe', 'release'))
    parser.add_argument('--work', type=Path, default=Path('/work'), choices=(Path('/work'),))
    parser.add_argument('--response', type=Path, default=Path('/production-response'),
                        choices=(Path('/production-response'),))
    args = parser.parse_args()
    print(json.dumps(continue_phase(args.phase, args.work, args.response), default=str), flush=True)


if __name__ == '__main__':
    main()
