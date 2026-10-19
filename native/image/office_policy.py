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


def package_stanzas(status):
    """Parse dpkg's UTF-8 deb822 status data without dropping continuations.

    Dpkg writes multiline fields such as ``Conffiles:`` with no first-line
    value. A colon, not the conventional colon-plus-space, separates a field.
    Field names are case insensitive; the authority-bearing simple fields may
    not acquire a hidden second line. Every stanza is parsed, including those
    for packages unrelated to this adapter.
    """
    text = status.decode('utf-8')
    if re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text):
        raise ValueError('invalid control character in package metadata')
    fields = {}
    previous = None
    simple = {'package', 'status', 'architecture', 'version'}
    for line in text.split('\n'):
        if not line.strip(' \t'):
            if fields:
                yield fields
            fields = {}
            previous = None
            continue
        if line.startswith((' ', '\t')):
            if previous is None or previous in simple:
                raise ValueError('invalid package metadata continuation')
            fields[previous] += '\n' + line[1:]
            continue
        key, separator, value = line.partition(':')
        if not separator or not re.fullmatch(r'[!-9;-~]+', key) or key.startswith(('#', '-')):
            raise ValueError('malformed package metadata field')
        key = key.lower()
        if key in fields:
            raise ValueError('ambiguous package metadata')
        fields[key] = value.strip(' \t')
        previous = key
    if fields:
        yield fields


def manifest(root):
    _, status = read(root, 'var/lib/dpkg/status', 16 * 1024 * 1024)
    installed = {}
    for fields in package_stanzas(status):
        if fields.get('package') in PACKAGES:
            name = fields['package']
            if name in installed or fields.get('status') != 'install ok installed' or fields.get('architecture') != 'amd64' or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}', fields.get('version', '')):
                raise ValueError('Office dependency package tuple refused')
            installed[name] = fields['version']
    if set(installed) != set(PACKAGES):
        raise ValueError('actual pinned image lacks required Office dependencies')
    files = [read(root, name, MAX_FILE, elf=True)[0] for name in FILES]
    return dict(schema_version=1, profile=PROFILE, packages=[dict(name=name, version=installed[name], architecture='amd64') for name in PACKAGES],
                files=files, input_profile='native-generated-inert-document-html-v1', output_media_type='application/pdf',
                max_input_bytes=1024*1024, max_output_bytes=16*1024*1024, timeout_seconds=30,
                memory_bytes=1024*1024*1024, tasks=32, native_qualified=False)


def canonical_manifest(root):
    return json.dumps(manifest(root), ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
