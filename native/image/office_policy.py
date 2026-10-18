"""Fingerprint the actual snapshot-installed, image-owned Office adapter.

Build data is not signer/custody/native qualification. No host package install,
version invention, executable stub or caller-selected adapter is supported.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PROFILE = 'libreoffice-document-html-pdf-v1'
PACKAGES = ('bubblewrap', 'libreoffice-core', 'libreoffice-writer')
FILES = ('usr/bin/bwrap', 'usr/lib/libreoffice/program/soffice.bin',
         'usr/lib/libreoffice/program/libmergedlo.so')
MAX_FILE = 256 * 1024 * 1024


def read(root, relative, maximum, *, elf=False):
    root = Path(root).resolve(strict=True)
    path = root / relative
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise ValueError('Office pin refuses source aliases or root escape')
    for parent in path.parents:
        if parent == root.parent:
            break
        item = parent.stat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise ValueError('Office image source ancestor is not root protected')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o7022 or not 0 < before.st_size <= maximum:
            raise ValueError('Office pin source metadata/bound refused')
        digest = hashlib.sha256()
        size = 0
        prefix = bytearray()
        retained = bytearray() if maximum <= 16 * 1024 * 1024 else None
        while size <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - size))
            if not block:
                break
            digest.update(block)
            if len(prefix) < 64:
                prefix.extend(block[:64-len(prefix)])
            size += len(block)
            if retained is not None:
                retained.extend(block)
        identity = lambda value: (value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if size != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.stat()):
            raise ValueError('Office image source changed while fingerprinting')
        if elf and (len(prefix) != 64 or prefix[:7] != b'\x7fELF\x02\x01\x01'
                    or int.from_bytes(prefix[16:18], 'little') not in (2, 3)
                    or int.from_bytes(prefix[18:20], 'little') != 62
                    or int.from_bytes(prefix[20:24], 'little') != 1):
            raise ValueError('Office adapter requires genuine compiled x86-64 ELF inputs')
        return dict(path='/' + relative, bytes=size, sha256=digest.hexdigest()), bytes(retained) if retained is not None else None
    finally:
        os.close(descriptor)


def manifest(root):
    _, status = read(root, 'var/lib/dpkg/status', 16 * 1024 * 1024)
    installed = {}
    for stanza in status.decode('utf-8').split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            if line and not line.startswith((' ', '\t')):
                key, separator, value = line.partition(': ')
                if not separator or key in fields:
                    raise ValueError('ambiguous package metadata')
                fields[key] = value
        if fields.get('Package') in PACKAGES:
            name = fields['Package']
            if name in installed or fields.get('Status') != 'install ok installed' or fields.get('Architecture') != 'amd64' or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', fields.get('Version', '')):
                raise ValueError('Office dependency package tuple refused')
            installed[name] = fields['Version']
    if set(installed) != set(PACKAGES):
        raise ValueError('actual pinned image lacks required Office dependencies')
    files = [read(root, name, MAX_FILE, elf=True)[0] for name in FILES]
    return dict(schema_version=1, profile=PROFILE, packages=[dict(name=name, version=installed[name], architecture='amd64') for name in PACKAGES],
                files=files, input_profile='native-generated-inert-document-html-v1', output_media_type='application/pdf',
                max_input_bytes=1024*1024, max_output_bytes=16*1024*1024, timeout_seconds=30,
                memory_bytes=1024*1024*1024, tasks=32, native_qualified=False)


def canonical_manifest(root):
    return json.dumps(manifest(root), ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
