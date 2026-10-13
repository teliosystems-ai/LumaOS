#!/usr/bin/env python3
"""Verify sealed laboratory build inputs and package them into fresh media.

This is a packaging continuation, not a rebuild, signing ceremony, installer,
or native qualification. The original captured product source is unchanged.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import uuid
import zlib

MIB = 1024 * 1024
SOURCE_SHA = '58be10695ba8165541d4f4caa0f1853190fcf62cb8177230d886e9234e509885'
SIGNED = ('root.ext4', 'root.verity', 'slot-a.efi', 'slot-b.efi',
          'bootloader.efi', 'secureboot.cer')
METADATA = ('release.json', 'release.sig', 'secureboot.cer', 'packages.lock',
            'source-lock.json', 'toolchain-packages.lock', 'native-source.tar.zst',
            'boot-policy.json')
LABELS = ('LUMA-LIVE-ESP', 'luma-live-root', 'luma-live-hash', 'luma-payload')
LINUX_GUID = uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4')
ESP_GUID = uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b')
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'LC_ALL': 'C',
       'SYSTEMD_LOG_LEVEL': 'err', 'TMPDIR': '/work/artifacts'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_file(path):
    with path.open('rb') as stream:
        return hash_stream(stream, path.stat().st_size)


def hash_stream(stream, size):
    value = hashlib.sha256()
    remaining = size
    while remaining:
        block = stream.read(min(MIB, remaining))
        if not block:
            raise ValueError('truncated regular artifact or image range')
        value.update(block)
        remaining -= len(block)
    return value.hexdigest()


def closed_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def relative_name(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValueError('invalid captured source path')
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value or '\\' in value
            or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('captured path escapes its immutable namespace')
    return path


def parse_manifest(raw):
    value = closed_json(raw)
    expected = {'schema_version', 'release', 'sequence', 'environment', 'architecture',
                'ubuntu', 'edition', 'root_hash', 'root_bytes', 'hash_bytes', 'artifacts'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('release manifest is not the closed laboratory schema')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['sequence']) is not int or not 1 <= value['sequence'] < 2**63
            or value['environment'] != 'lab' or value['architecture'] != 'amd64'
            or value['ubuntu'] != '24.04' or value['edition'] not in ('desktop', 'headless')
            or value['release'] != f"luma-native-lab-20260927-{value['edition']}-{value['sequence']}"
            or not hash_value(value['root_hash'])):
        raise ValueError('release identity/environment/purpose is not this laboratory build')
    root_mib, _ = geometry(value['edition'])
    if (type(value['root_bytes']) is not int or value['root_bytes'] != root_mib * MIB
            or type(value['hash_bytes']) is not int or not 1 <= value['hash_bytes'] <= 64 * MIB
            or not isinstance(value['artifacts'], list) or len(value['artifacts']) != len(SIGNED)):
        raise ValueError('release partition sizes or artifact count differ')
    entries = {}
    for entry in value['artifacts']:
        if (not isinstance(entry, dict) or set(entry) != {'name', 'bytes', 'sha256'}
                or entry['name'] not in SIGNED or entry['name'] in entries
                or type(entry['bytes']) is not int or entry['bytes'] < 1
                or not hash_value(entry['sha256'])):
            raise ValueError('release artifact path/digest/inventory differs')
        maximum = (root_mib * MIB if entry['name'] == 'root.ext4' else
                   64 * MIB if entry['name'] == 'root.verity' else
                   16384 if entry['name'] == 'secureboot.cer' else 256 * MIB)
        if entry['bytes'] > maximum:
            raise ValueError('signed artifact exceeds its exact packaging bound')
        entries[entry['name']] = entry
    if (entries['root.ext4']['bytes'] != value['root_bytes']
            or entries['root.verity']['bytes'] != value['hash_bytes']):
        raise ValueError('signed root/verity sizes disagree')
    return value


def parse_source_lock(raw, expected_sha):
    if not hash_value(expected_sha) or sha(raw) != expected_sha:
        raise ValueError('captured source lock differs from independently expected SHA256')
    value = closed_json(raw)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'files'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['files'], list) or len(value['files']) != 314):
        raise ValueError('captured source lock must contain the original 314 files')
    result = {}
    total = 0
    for entry in value['files']:
        if (not isinstance(entry, dict) or set(entry) != {'path', 'bytes', 'sha256'}
                or type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= 32 * MIB
                or not hash_value(entry['sha256'])):
            raise ValueError('invalid captured source descriptor')
        name = relative_name(entry['path']).as_posix()
        if name in result:
            raise ValueError('duplicate captured source file')
        result[name] = entry
        total += entry['bytes']
    if list(result) != sorted(result) or total > 256 * MIB:
        raise ValueError('captured source inventory order or total bound differs')
    return result


def geometry(edition):
    if edition == 'desktop':
        return 6144, 8192
    if edition == 'headless':
        return 4096, 6144
    raise ValueError('unknown image edition')


def layout(edition):
    root, payload = geometry(edition)
    sizes = [1024 * MIB, root * MIB, 64 * MIB, payload * MIB]
    start = MIB
    entries = []
    for index, (size, label) in enumerate(zip(sizes, LABELS)):
        entries.append({'offset': start, 'bytes': size, 'label': label,
                        'type': ESP_GUID if index == 0 else LINUX_GUID})
        start += size
    return entries, sum(sizes) + 16 * MIB


def witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class Pins:
    def __init__(self):
        self.files = []

    def capture(self, path, maximum):
        for parent in path.parents:
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ValueError('artifact parent is linked or not a directory')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= maximum:
            raise ValueError('input is linked, special or outside its regular-file bound')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
        stream = os.fdopen(descriptor, 'rb')
        if witness(os.fstat(descriptor)) != witness(info):
            stream.close()
            raise ValueError('input changed during descriptor capture')
        parents = [(parent, witness(parent.lstat())[:4]) for parent in path.parents]
        self.files.append((path, stream, witness(info), parents))
        return path

    def recheck(self):
        for path, stream, expected, parents in self.files:
            if witness(path.lstat()) != expected or witness(os.fstat(stream.fileno())) != expected:
                raise ValueError('retained packaging input changed')
            for parent, identity in parents:
                if witness(parent.lstat())[:4] != identity:
                    raise ValueError('retained packaging namespace changed')

    def close(self):
        for _, stream, _, _ in self.files:
            stream.close()


def run(*arguments, timeout=300):
    """Drain both tool pipes with explicit output and wall-clock bounds."""
    child = subprocess.Popen([str(a) for a in arguments], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    streams = selectors.DefaultSelector()
    streams.register(child.stdout, selectors.EVENT_READ, 'out')
    streams.register(child.stderr, selectors.EVENT_READ, 'err')
    output = {'out': bytearray(), 'err': bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('packaging verifier command exceeded its deadline')
            for key, _ in streams.select(min(remaining, 1)):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    streams.unregister(key.fileobj)
                    continue
                output[key.data].extend(block)
                if len(output[key.data]) > 4 * MIB:
                    raise ValueError('packaging verifier command exceeded its output bound')
        status = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if status != 0:
            raise ValueError('packaging verifier failed: ' + str(arguments[0]) + ': '
                             + output['err'].decode('utf-8', 'replace')[-4096:])
        return bytes(output['out']).decode('utf-8', 'strict')
    finally:
        streams.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stderr.close()


def require_readonly(path):
    if not exact_mount(path) or not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError('input must be its exact read-only directory mount')
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError('resume input mount is not read-only')


def mountpoint_in(raw, path):
    if len(raw) > MIB:
        raise ValueError('mount inventory exceeds bound')
    matches = 0
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields[6:] or not fields[0].isdecimal():
            raise ValueError('invalid kernel mount inventory')
        value = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), fields[4])
        matches += value == str(path)
    return matches == 1


def exact_mount(path):
    with Path('/proc/self/mountinfo').open('r', encoding='utf-8') as stream:
        raw = stream.read(MIB + 1)
    return mountpoint_in(raw, path)


def prepare_output(path, required_bytes):
    if not stat.S_ISDIR(path.lstat().st_mode) or any(path.iterdir()):
        raise ValueError('resume output must be a fresh empty directory; existing raw is preserved')
    if os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError('resume output is read-only')
    if shutil.disk_usage(path).free < required_bytes:
        raise ValueError('fresh output lacks bounded raw/compressed/headroom capacity')
    marker = path/'.resume-in-progress.json'
    with marker.open('xb') as stream:
        stream.write(b'{"schema_version":1,"status":"verification-and-packaging-in-progress"}\n')
        stream.flush()
        os.fsync(stream.fileno())


def load_module(repo, name):
    spec = importlib.util.spec_from_file_location('luma_frozen_' + name,
                                                repo/'native/image'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_source_tree(repo, entries, pins, source_lock_bytes=None):
    actual = set()
    for directory, folders, files in os.walk(repo, followlinks=False):
        for name in folders:
            if not stat.S_ISDIR((Path(directory)/name).lstat().st_mode):
                raise ValueError('source snapshot contains linked directories')
        for name in files:
            path = Path(directory)/name
            relative = path.relative_to(repo).as_posix()
            if relative == 'build-inputs.json' and source_lock_bytes is not None:
                pins.capture(path, len(source_lock_bytes))
                if path.read_bytes() != source_lock_bytes:
                    raise ValueError('captured builder metadata differs from pinned source lock')
                continue
            if relative not in entries:
                raise ValueError('source snapshot contains undeclared file')
            descriptor = entries[relative]
            pins.capture(path, descriptor['bytes'])
            if path.stat().st_size != descriptor['bytes'] or hash_file(path) != descriptor['sha256']:
                raise ValueError('captured source snapshot bytes differ')
            actual.add(relative)
    if actual != set(entries):
        raise ValueError('captured source snapshot is incomplete')


class BudgetReader:
    def __init__(self, stream, maximum):
        self.stream, self.remaining = stream, maximum

    def read(self, size=-1):
        if self.remaining <= 0:
            if self.stream.read(1):
                raise ValueError('source archive expanded beyond its exact bounded inventory')
            return b''
        raw = self.stream.read(min(self.remaining, 65536 if size < 0 else size))
        self.remaining -= len(raw)
        return raw


class DeadlineReader:
    """Bound the reads themselves, not just wait() after an unbounded pipe."""
    def __init__(self, stream, seconds):
        self.stream = stream
        self.deadline = time.monotonic() + seconds
        self.selector = selectors.DefaultSelector()
        self.selector.register(stream, selectors.EVENT_READ)
        os.set_blocking(stream.fileno(), False)

    def read(self, size=-1):
        size = min(65536, size if size >= 0 else 65536)
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise ValueError('streamed artifact verification exceeded its deadline')
            try:
                return os.read(self.stream.fileno(), size)
            except BlockingIOError:
                continue

    def close(self):
        self.selector.close()


def check_source_archive(stream, entries):
    budget = BudgetReader(stream, sum(item['bytes'] for item in entries.values()) + 16 * MIB)
    ancestors = {'.'}
    for name in entries:
        ancestors.update(parent.as_posix() for parent in PurePosixPath(name).parents)
    seen, directories = set(), set()
    # A tar reader can consume undeclared trailing bytes into an internal
    # buffer. Spool only this bounded source archive (never filesystem images)
    # and inspect the complete physical tail after its final declared member.
    with tempfile.TemporaryFile() as frozen:
        while block := budget.read(65536):
            frozen.write(block)
        frozen.seek(0)
        archive = tarfile.open(fileobj=frozen, mode='r:')
        end = 0
        for member in archive:
            end = max(end, member.offset_data + ((member.size + 511) // 512) * 512)
            raw = member.name
            name = raw[2:] if raw.startswith('./') else raw
            name = name.rstrip('/') if member.isdir() else name
            if name == '.' or name == '':
                if not member.isdir() or '.' in directories:
                    raise ValueError('invalid archive root member')
                directories.add('.')
                continue
            relative_name(name)
            if member.isdir():
                if name not in ancestors or name in directories:
                    raise ValueError('undeclared or duplicate source archive directory')
                directories.add(name)
                continue
            if not member.isfile() or name not in entries or name in seen:
                raise ValueError('archive has undeclared, duplicate, linked or special member')
            expected = entries[name]
            if member.size != expected['bytes']:
                raise ValueError('source archive file size differs')
            with archive.extractfile(member) as source:
                if hash_stream(source, member.size) != expected['sha256']:
                    raise ValueError('source archive file digest differs')
            seen.add(name)
        archive.close()
        if seen != set(entries):
            raise ValueError('source archive is missing captured files')
        frozen.seek(end)
        while tail := frozen.read(65536):
            if any(tail):
                raise ValueError('source archive has undeclared trailing content')


def verify_compressed_source(path, entries):
    with tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(['zstd', '-dc', str(path)], stdout=subprocess.PIPE,
                                 stderr=errors, stdin=subprocess.DEVNULL, env=ENV)
        reader = DeadlineReader(child.stdout, 120)
        try:
            check_source_archive(reader, entries)
            if child.wait(timeout=120) != 0:
                raise ValueError('captured compressed source archive is invalid')
        finally:
            reader.close()
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()


def ext4_entries(image, directory):
    output = run('debugfs', '-R', 'ls -p ' + directory, image)
    entries = {}
    for line in output.splitlines():
        if not line:
            continue
        pieces = line.split('/')
        if len(pieces) != 8 or pieces[0] or pieces[-1]:
            raise ValueError('unexpected debugfs inventory format')
        _, inode, mode, uid, gid, name, size, _ = pieces
        # debugfs prints preallocated empty directory slots, notably in
        # lost+found. These have no inode or name and are not filesystem
        # members. Accept only its exact canonical empty-slot encoding.
        if pieces == ['', '0', '000000', '0', '0', '', '0', '']:
            continue
        if name in ('.', '..'):
            continue
        if (not inode.isdecimal() or int(inode) == 0 or not uid.isdecimal()
                or not gid.isdecimal() or not re.fullmatch('[0-7]{6}', mode)
                or name in entries or '/' in name):
            raise ValueError('invalid or duplicated ext4 member')
        entries[name] = (int(mode, 8), int(size) if size else None)
    return entries


def ext4_member_size(image, source, maximum):
    if not re.fullmatch('/[A-Za-z0-9_./+-]+', source):
        raise ValueError('unsafe fixed ext4 extraction path')
    output = run('debugfs', '-R', 'stat ' + source, image)
    size = re.search(r'\bSize:\s*([0-9]+)', output)
    if ('Type: regular' not in output or not size or int(size[1]) > maximum
            or not re.search(r'\bLinks:\s*1\b', output)):
        raise ValueError('ext4 member is not a bounded, single-link regular file')
    return int(size[1])


def extract_ext4(image, source, target, maximum):
    size = ext4_member_size(image, source, maximum)
    if target.exists() or target.is_symlink():
        raise ValueError('refusing existing extraction target')
    run('debugfs', '-R', f'dump {source} {target}', image)
    if not target.is_file() or target.is_symlink() or target.stat().st_size != size:
        raise ValueError('ext4 extraction failed or changed size')
    return target


def verify_payload(previous, scratch):
    expected = set(SIGNED) | {'release.json', 'release.sig', 'packages.lock'}
    entries = ext4_entries(previous/'payload.ext4', '/')
    if set(entries) != expected | {'lost+found'} or entries['lost+found'][0] & 0o170000 != stat.S_IFDIR:
        raise ValueError('payload ext4 has undeclared members or missing recovery directory')
    if ext4_entries(previous/'payload.ext4', '/lost+found'):
        raise ValueError('payload lost+found contains undeclared content')
    for index, name in enumerate(sorted(expected)):
        if entries[name][0] & 0o170000 != stat.S_IFREG:
            raise ValueError('payload contains linked or special member')
        original = previous/name
        if (entries[name][1] != original.stat().st_size
                or ext4_member_size(previous/'payload.ext4', '/' + name,
                                    original.stat().st_size) != original.stat().st_size):
            raise ValueError('payload member size/link metadata differs')
        # Root extraction would duplicate 6 GiB. Stream debugfs cat for that
        # one member and verify its complete hash without a writable copy.
        if name == 'root.ext4':
            with tempfile.TemporaryFile() as errors:
                child = subprocess.Popen(['debugfs', '-R', 'cat /' + name,
                                          str(previous/'payload.ext4')], stdout=subprocess.PIPE,
                                         stderr=errors, stdin=subprocess.DEVNULL, env=ENV)
                reader = DeadlineReader(child.stdout, 1800)
                try:
                    if (hash_stream(reader, original.stat().st_size) != hash_file(original)
                            or reader.read(1) or child.wait(timeout=120) != 0):
                        raise ValueError('payload root image bytes differ')
                finally:
                    reader.close()
                    if child.poll() is None:
                        child.kill()
                    child.wait()
                    child.stdout.close()
        else:
            extracted = extract_ext4(previous/'payload.ext4', '/' + name,
                                     scratch/f'payload-{index}', original.stat().st_size)
            if hash_file(extracted) != hash_file(original):
                raise ValueError('payload member bytes differ from verified artifacts')


def verify_esp(previous, scratch):
    expected = {'efi/boot/bootx64.efi': 'bootloader.efi',
                'efi/linux/luma-live.efi': 'slot-live.efi',
                'secureboot.cer': 'secureboot.cer', 'loader/loader.conf': 'loader.conf'}
    directories = {'efi', 'efi/boot', 'efi/linux', 'loader'}
    listing = run('mdir', '-i', previous/'esp.fat', '-b', '-s', '::/').splitlines()
    actual = set()
    for line in listing:
        if not line.startswith('::/'):
            raise ValueError('unexpected FAT inventory format')
        name = line[3:].rstrip('/').lower()
        relative_name(name)
        if name in actual:
            raise ValueError('duplicate FAT member')
        actual.add(name)
    if actual != set(expected) | directories:
        raise ValueError('ESP contains undeclared or missing members')
    for index, (name, original) in enumerate(expected.items()):
        destination = scratch/f'esp-{index}'
        run('mcopy', '-i', previous/'esp.fat', '::/' + name, destination)
        if destination.is_symlink() or not destination.is_file():
            raise ValueError('ESP extraction did not produce a regular file')
        if hash_file(destination) != hash_file(previous/original):
            raise ValueError('ESP member bytes differ from verified artifacts')
    if (previous/'loader.conf').read_bytes() != b'default luma-live.efi\ntimeout 3\neditor no\n':
        raise ValueError('live boot menu differs from its closed policy')


def verify_gpt(image, edition):
    partitions, total = layout(edition)
    if image.stat().st_size != total:
        raise ValueError('raw image size differs from closed geometry')
    sectors = total // 512
    with image.open('rb') as stream:
        mbr = stream.read(512)
        if (mbr[510:] != b'\x55\xaa' or mbr[446] != 0 or mbr[450] != 0xee
                or struct.unpack('<II', mbr[454:462]) != (1, min(sectors - 1, 0xffffffff))
                or any(mbr[462:510]) or any(mbr[:440])):
            raise ValueError('missing protective GPT MBR')
        headers = []
        for location, other in [(1, sectors - 1), (sectors - 1, 1)]:
            stream.seek(location * 512)
            raw = stream.read(512)
            fields = struct.unpack('<8sIIIIQQQQ16sQIII', raw[:92])
            signature, revision, size, crc, reserved, current, backup, first, last, guid, entries, count, width, array_crc = fields
            cleared = bytearray(raw[:92])
            cleared[16:20] = bytes(4)
            if (signature != b'EFI PART' or revision != 0x10000 or size != 92
                    or reserved or current != location or backup != other
                    or first != 34 or last != sectors - 34 or not any(guid)
                    or count != 128 or width != 128
                    or entries != (2 if location == 1 else sectors - 33)
                    or zlib.crc32(cleared) != crc or any(raw[92:])):
                raise ValueError('GPT header geometry or CRC differs')
            stream.seek(entries * 512)
            table = stream.read(count * width)
            if zlib.crc32(table) != array_crc:
                raise ValueError('GPT partition array CRC differs')
            headers.append((guid, table))
        if headers[0] != headers[1]:
            raise ValueError('primary/backup GPT disagree')
        table = headers[0][1]
        identities = set()
        for index, expected in enumerate(partitions):
            entry = table[index * 128:(index + 1) * 128]
            kind, identifier, begin, end, attributes, label = struct.unpack('<16s16sQQQ72s', entry)
            if (uuid.UUID(bytes_le=kind) != expected['type'] or not any(identifier)
                    or identifier in identities or attributes
                    or begin * 512 != expected['offset']
                    or (end - begin + 1) * 512 != expected['bytes']
                    or label.decode('utf-16-le').rstrip('\0') != expected['label']):
                raise ValueError('GPT partition type/label/offset/bound differs')
            identities.add(identifier)
        if any(table[4 * 128:]):
            raise ValueError('GPT contains undeclared partitions')
    return partitions


def verify_ranges(image, sources, partitions):
    if len(sources) != 4 or len(partitions) != 4:
        raise ValueError('copy verification requires all four exact partitions')
    with image.open('rb') as stream:
        for source, partition in zip(sources, partitions):
            size = source.stat().st_size
            if size > partition['bytes']:
                raise ValueError('artifact exceeds its reserved image partition')
            stream.seek(partition['offset'])
            if hash_stream(stream, size) != hash_file(source):
                raise ValueError('copied image partition range differs from verified input')
            remaining = partition['bytes'] - size
            while remaining:
                block = stream.read(min(MIB, remaining))
                if not block or any(block):
                    raise ValueError('partition slack contains undeclared content')
                remaining -= len(block)


def desktop_report(root, edition, policy):
    if policy.geometry(edition) != geometry(edition):
        raise ValueError('captured desktop geometry differs from packaging contract')
    if edition == 'headless':
        if (root/'usr/share/luma-os/desktop-profile').exists():
            raise ValueError('headless root unexpectedly declares graphical profile')
        return {'profile': 'console', 'wayland_session_tested': False}
    for name in policy.REQUIRED:
        path = root/name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError('captured desktop prerequisite is absent or substituted')
    if ((root/'usr/share/luma-os/desktop-profile').read_text() != policy.PROFILE + '\n'
            or (root/'usr/libexec/luma-os/luma-wayland-session').read_text() != policy.SESSION):
        raise ValueError('captured desktop/session policy differs')
    return {'profile': policy.PROFILE, 'wayland_session_tested': False,
            'model_required_for_login': False, 'live_graphical_login': False}


def check_release_identity(raw, release_id, manifest):
    expected = {key: manifest[key] for key in
                ('schema_version', 'release', 'sequence', 'environment', 'architecture', 'ubuntu', 'edition')}
    if closed_json(raw) != expected or release_id != (manifest['release'] + '\n').encode():
        raise ValueError('root embedded release identity differs from signed manifest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-lock', 'release-public', 'secureboot-cert', 'pcr-public'):
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    parser.add_argument('--rootfs', type=Path, default=Path('/rootfs'),
                        choices=(Path('/rootfs'), Path('/retained/root')),
                        help='read-only retained build root; no product rebuild or host root')
    arguments = parser.parse_args()
    expected = {name: getattr(arguments, 'expected_' + name.replace('-', '_') + '_sha256')
                for name in ('source-lock', 'release-public', 'secureboot-cert', 'pcr-public')}
    if expected['source-lock'] != SOURCE_SHA or not all(hash_value(v) for v in expected.values()):
        raise ValueError('resume requires independently pinned source/key/certificate fingerprints')
    previous, repo, out = map(Path, ('/previous', '/repo', '/work/artifacts'))
    root = arguments.rootfs
    if os.name != 'posix' or os.uname().machine != 'x86_64' or os.geteuid() != 0:
        raise ValueError('resume packaging requires the isolated amd64 root tool container')
    for path in (previous, repo, root if root == Path('/rootfs') else root.parent):
        require_readonly(path)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('retained build root is linked or not a directory')
    if not exact_mount(out):
        raise ValueError('output must be its fresh dedicated ext4 mount')
    # Linux statfs f_type is the first native long; the backing mount must be
    # ext4, never the NTFS/drvfs filesystem that interrupted the previous copy.
    buffer = ctypes.create_string_buffer(256)
    if ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(out), buffer) != 0:
        raise OSError(ctypes.get_errno(), 'output statfs failed')
    if ctypes.c_long.from_buffer(buffer).value != 0xef53:
        raise ValueError('fresh output must be ext4-backed')
    pins = Pins()
    try:
        release = pins.capture(previous/'release.json', MIB)
        manifest = parse_manifest(release.read_bytes())
        _, total = layout(manifest['edition'])
        prepare_output(out, total * 2 + 1024 * MIB)
        for name in METADATA:
            pins.capture(previous/name, 256 * MIB if name == 'native-source.tar.zst' else 16 * MIB)
        entries = parse_source_lock((previous/'source-lock.json').read_bytes(), expected['source-lock'])
        print('Resume: verifying original captured source and source archive', flush=True)
        check_source_tree(repo, entries, pins, (previous/'source-lock.json').read_bytes())
        verify_compressed_source(previous/'native-source.tar.zst', entries)
        assembler = load_module(repo, 'assemble')
        boot = load_module(repo, 'boot_policy')
        desktop = load_module(repo, 'desktop_policy')
        shutdown = load_module(repo, 'shutdown_policy')
        report = desktop_report(root, manifest['edition'], desktop)
        for entry in manifest['artifacts']:
            path = pins.capture(previous/entry['name'], entry['bytes'])
            if path.stat().st_size != entry['bytes'] or hash_file(path) != entry['sha256']:
                raise ValueError('sealed signed artifact size/digest differs')
        print('Resume: signed artifact hashes verified; checking embedded identities and UKIs', flush=True)
        partitions, _ = layout(manifest['edition'])
        for name, bound in [('slot-live.efi', 256 * MIB), ('esp.fat', partitions[0]['bytes']),
                            ('payload.ext4', partitions[3]['bytes']), ('loader.conf', 4096)]:
            path = pins.capture(previous/name, bound)
            if name in ('esp.fat', 'payload.ext4') and path.stat().st_size != bound:
                raise ValueError('retained filesystem image size differs from partition')
        if (previous/'release.sig').stat().st_size != 64:
            raise ValueError('Ed25519 release signature must be exactly 64 bytes')
        with tempfile.TemporaryDirectory(prefix='.resume-verification-', dir=out) as temporary:
            scratch = Path(temporary)
            public = pins.capture(root/'usr/share/luma-os/release.pub', 16384)
            pcr = pins.capture(root/'usr/share/luma-os/admin-pcr-public.pem', 16384)
            for path, fingerprint in [(public, expected['release-public']),
                                      (pcr, expected['pcr-public']),
                                      (previous/'secureboot.cer', expected['secureboot-cert'])]:
                if hash_file(path) != fingerprint:
                    raise ValueError('independently pinned public custody fingerprint differs')
            lock = pins.capture(root/'usr/share/luma-os/source-lock.json', 16 * MIB)
            if lock.read_bytes() != (previous/'source-lock.json').read_bytes():
                raise ValueError('embedded root source lock differs from independently pinned source')
            for index, original in enumerate((public, pcr, lock)):
                extracted = extract_ext4(previous/'root.ext4', '/' + original.relative_to(root).as_posix(),
                                         scratch/f'root-public-{index}', 16 * MIB)
                if hash_file(extracted) != hash_file(original):
                    raise ValueError('root image embedded public/source identity differs')
            identities = []
            for index, name in enumerate(('release-identity.json', 'release-id')):
                original = pins.capture(root/'usr/share/luma-os'/name, 16384)
                extracted = extract_ext4(previous/'root.ext4', '/usr/share/luma-os/' + name,
                                         scratch/f'root-identity-{index}', 16384)
                if extracted.read_bytes() != original.read_bytes():
                    raise ValueError('retained root release identity differs from actual image')
                identities.append(extracted.read_bytes())
            check_release_identity(identities[0], identities[1], manifest)
            if manifest['edition'] == 'desktop':
                for index, name in enumerate(('usr/share/luma-os/desktop-profile',
                                               'usr/libexec/luma-os/luma-wayland-session')):
                    original = pins.capture(root/name, 16384)
                    extracted = extract_ext4(previous/'root.ext4', '/' + name,
                                             scratch/f'root-desktop-{index}', 16384)
                    if extracted.read_bytes() != original.read_bytes():
                        raise ValueError('actual image desktop profile differs from introspection')
            run('openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', public,
                '-in', release, '-sigfile', previous/'release.sig')
            run('veritysetup', 'verify', previous/'root.ext4', previous/'root.verity',
                manifest['root_hash'], timeout=1800)
            certificate = scratch/'secureboot.pem'
            run('openssl', 'x509', '-inform', 'DER', '-in', previous/'secureboot.cer',
                '-out', certificate)
            if run('openssl', 'x509', '-in', certificate, '-noout', '-subject',
                   '-nameopt', 'RFC2253').strip() != 'subject=CN=Luma Native Laboratory Only':
                raise ValueError('certificate is not laboratory Secure Boot custody')
            kernels = list((root/'boot').glob('vmlinuz-*-generic'))
            if len(kernels) != 1:
                raise ValueError('retained root must contain exactly one generic kernel')
            kernel = pins.capture(kernels[0], 128 * MIB)
            initrd = pins.capture(root/'boot/luma-initrd', 256 * MIB)
            version = kernel.name.removeprefix('vmlinuz-')
            if not re.fullmatch('[0-9][A-Za-z0-9.+_-]{0,95}', version):
                raise ValueError('retained kernel version differs')
            for index, source in enumerate((kernel, initrd)):
                extracted = extract_ext4(previous/'root.ext4', '/' + source.relative_to(root).as_posix(),
                                         scratch/f'root-boot-{index}', source.stat().st_size)
                if hash_file(extracted) != hash_file(source):
                    raise ValueError('root image kernel/initrd differs from retained build root')
            initrd_policy = boot.verify_initrd(initrd)
            initrd_policy['shutdown'] = shutdown.verify_initrd(initrd)
            records = []
            for slot in ('a', 'b', 'live'):
                image = previous/f'slot-{slot}.efi'
                records.append(boot.verify_uki(image, slot, pcr.read_bytes(), certificate))
                sections = boot.read_sections(image)
                mode = 'live' if slot == 'live' else 'installed'
                desktop.verify_boot_target(sections['.cmdline'], manifest['edition'], mode)
                expected_words = (
                    'root=/dev/mapper/root ro roothash=' + manifest['root_hash'] +
                    ' systemd.verity_root_options=panic-on-corruption' +
                    ' systemd.verity_root_data=/dev/disk/by-partlabel/' +
                    ('luma-live-root' if slot == 'live' else 'luma-root-' + slot) +
                    ' systemd.verity_root_hash=/dev/disk/by-partlabel/' +
                    ('luma-live-hash' if slot == 'live' else 'luma-hash-' + slot) +
                    f' luma.mode={mode} luma.slot={slot} systemd.unit=' + desktop.target(manifest['edition'], mode) +
                    ' console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor' +
                    ' systemd.show_status=yes rd.shell=0 panic=10').encode()
                if (sections['.cmdline'].rstrip(b'\0') != expected_words
                        or sections['.linux'] != kernel.read_bytes()
                        or sections['.initrd'] != initrd.read_bytes()
                        or sections['.uname'].rstrip(b'\0') != version.encode()):
                    raise ValueError('UKI measured root/kernel/initrd/command line differs')
                osrel = (f'ID=luma\nNAME="Luma Native Laboratory"\nVERSION_ID={manifest["sequence"]}\n'
                         f'PRETTY_NAME="{manifest["release"]}"\n').encode()
                if sections['.osrel'].rstrip(b'\0') != osrel:
                    raise ValueError('UKI measured release identity differs')
            policy = closed_json((previous/'boot-policy.json').read_bytes())
            if policy != {'schema_version': 1, 'environment': 'lab', 'slots': records,
                          'initrd': initrd_policy, 'enrollment_active': False, 'gate_closing': False}:
                raise ValueError('retained boot-policy report differs from actual verification')
            run('sbverify', '--cert', certificate, previous/'bootloader.efi')
            print('Resume: boot/verity verified; checking exact payload and ESP content', flush=True)
            verify_payload(previous, scratch)
            verify_esp(previous, scratch)
            pins.recheck()
        for name in METADATA:
            with (previous/name).open('rb') as source, (out/name).open('xb') as target:
                shutil.copyfileobj(source, target, MIB)
                target.flush()
                os.fsync(target.fileno())
            if hash_file(out/name) != hash_file(previous/name):
                raise ValueError('fresh copied metadata differs')
        image = out/(manifest['release'] + '.img')
        print('Resume: constructing new regular-file GPT image; old raw remains untouched', flush=True)
        with image.open('xb') as stream:
            stream.truncate(total)
            stream.flush()
            os.fsync(stream.fileno())
        argv = ['sgdisk', '--clear']
        for index, entry in enumerate(partitions, 1):
            start = entry['offset'] // 512
            end = (entry['offset'] + entry['bytes']) // 512 - 1
            argv += ['--new', f'{index}:{start}:{end}', '--change-name', f'{index}:{entry["label"]}',
                     '--typecode', f'{index}:{"ef00" if index == 1 else "8300"}']
        run(*argv, image)
        sources = [previous/name for name in ('esp.fat', 'root.ext4', 'root.verity', 'payload.ext4')]
        for source, entry in zip(sources, partitions):
            print('Resume: sparse-copy ' + source.name, flush=True)
            assembler.sparse_copy(source, image, entry['offset'])
        run('sgdisk', '--verify', image)
        verify_gpt(image, manifest['edition'])
        verify_ranges(image, sources, partitions)
        pins.recheck()
        print('Resume: GPT and copied ranges verified; compressing with two zstd threads', flush=True)
        compressed = Path(str(image) + '.zst')
        if compressed.exists() or compressed.is_symlink():
            raise ValueError('refusing existing compressed image')
        run('zstd', '-T2', '-3', image, '-o', compressed, timeout=7200)
        run('zstd', '-t', compressed, timeout=1800)
        with tempfile.TemporaryFile() as errors:
            child = subprocess.Popen(['zstd', '-dc', str(compressed)], stdout=subprocess.PIPE,
                                     stderr=errors, stdin=subprocess.DEVNULL, env=ENV)
            reader = DeadlineReader(child.stdout, 1800)
            try:
                image_sha = hash_file(image)
                if (hash_stream(reader, total) != image_sha or reader.read(1)
                        or child.wait(timeout=120) != 0):
                    raise ValueError('compressed final image does not reproduce exact raw bytes')
            finally:
                reader.close()
                if child.poll() is None:
                    child.kill()
                child.wait()
                child.stdout.close()
        pins.recheck()
        selected = [image, compressed] + [out/name for name in METADATA]
        with (out/'SHA256SUMS').open('x', encoding='utf-8') as stream:
            stream.write(''.join(f'{hash_file(path)}  {path.name}\n' for path in selected))
            stream.flush()
            os.fsync(stream.fileno())
        record = {'status': 'built-not-yet-boot-tested', 'release': manifest['release'],
                  'kernel': version, 'edition': manifest['edition'], 'root_hash': manifest['root_hash'],
                  'image': image.name, 'image_sha256': image_sha,
                  'source_lock_sha256': expected['source-lock'], 'desktop': report,
                  'production_signed': False, 'gate_closing': False,
                  'resume': {'schema_version': 1, 'operation': 'verify-and-package-sealed-lab-inputs',
                             'source_files_verified': len(entries), 'private_keys_used': False,
                             'product_rebuilt': False, 'native_qualification_claimed': False,
                             'packager_sha256': hash_file(Path(__file__)),
                             'frozen_assembler_sha256': entries['native/image/assemble.py']['sha256'],
                             'public_fingerprints': expected}}
        with (out/'build.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(record, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        # Remove only our exact inert progress marker after all final files
        # have been durably written; interrupted raw artifacts are never erased.
        (out/'.resume-in-progress.json').unlink()
        descriptor = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print(json.dumps(record, indent=2), flush=True)
    finally:
        pins.close()


if __name__ == '__main__':
    main()
