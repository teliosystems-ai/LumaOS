#!/usr/bin/env python3
"""Offline raw live-installer -> Hyper-V VHDX DATA staging, never VM deployment.

The caller supplies independent raw-image and actual qemu-img ELF SHA256 pins.
Production entry points require the existing desktop GPT geometry and a read-only
input mount. Signatures/custody are established by the separate image verifier,
not by a conversion manifest. Failed new outputs remain for diagnosis.

Format references: QEMU tools/qemu-img and system/images (VHDX); Microsoft VHDX
format. No guest is executed, mounted, installed, cloned, or enrolled here.
"""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import struct
import subprocess
import sys
import time
import uuid

MIB = 1024 * 1024
DESKTOP_BYTES = 16190013440
MAX_RAW = 64 * 1024**3
BLOCK = 2 * MIB
OPTIONS = 'subformat=dynamic,block_size=2097152,log_size=1048576,block_state_zero=on'
OUTPUT = 'luma-hyperv-live-installer.vhdx'
PRIVATE_STAGE = Path('/mnt/luma-build/work')
PUBLIC_EXPORT = Path('/mnt/d/LumaOS-builds')


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value), 'canonical SHA256 pin required')
    return value


def witness(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def parents(path):
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'canonical absolute path required')
    values = []
    for parent in path.parents:
        value = parent.lstat()
        require(stat.S_ISDIR(value.st_mode), 'input/output ancestors must not be links')
        values.append((parent, witness(value)[:5]))
    return values


def check_parents(values):
    for path, expected in values:
        require(witness(path.lstat())[:5] == expected, 'held namespace changed')


def writable_ext4(fd):
    buffer = ctypes.create_string_buffer(256)
    library = ctypes.CDLL(None, use_errno=True)
    library.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
    library.fstatfs.restype = ctypes.c_int
    if library.fstatfs(fd, buffer) != 0:
        raise OSError(ctypes.get_errno(), 'held output filesystem inspection failed')
    require(ctypes.c_long.from_buffer(buffer).value == 0xef53
            and not os.fstatvfs(fd).f_flag & os.ST_RDONLY,
            'VHDX staging requires an actual writable private ext4 filesystem')


class OutputDirectory:
    """One newly created object; names can never redirect its child writes.

    The namespace check detects rename/substitution, but is NOT the write
    containment boundary. All effects, including forensic records after a
    rename, use only the retained directory descriptor and constant basenames.
    Creation requires an entirely root-owned, non-other-writable ancestor chain
    and ext4. This excludes public/exFAT construction. It does not protect from
    concurrent trusted root actors, reserve storage, or establish custody.
    """
    def __init__(self, path):
        self.path = Path(path)
        self.parents = parents(self.path)
        self.ancestors = []
        self.parent_fd = None
        self.fd = None
        self.created = False
        try:
            require(os.geteuid() == 0 and len(self.path.parts) <= 32,
                    'bounded trusted-root private staging required')
            # mkdir has no returned object handle. Its name cannot safely be
            # reopened under an attacker-writable parent: even a plain existing
            # directory could be substituted between mkdirat and openat.
            # Pin and validate EVERY ancestor before the first mutation.
            current = Path('/')
            for index, part in enumerate(self.path.parent.parts):
                if index == 0:
                    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                else:
                    current = current / part
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.ancestors[-1][1])
                value = os.fstat(fd)
                self.ancestors.append((current, fd, witness(value)[:5]))
                require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0
                        and not value.st_mode & 0o022,
                        'output construction ancestor is not root-owned and protected')
            self.parent_fd = self.ancestors[-1][1]
            require(witness(os.fstat(self.parent_fd))[:5] == self.parents[0][1],
                    'selected output parent changed before creation')
            check_parents(self.parents)
            writable_ext4(self.parent_fd)
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent_fd)
            self.created = True
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY
                              | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
            new = os.fstat(self.fd)
            require(new.st_uid == 0 and stat.S_IMODE(new.st_mode) == 0o700
                    and not os.listdir(self.fd), 'new output directory is not private root-owned empty staging')
            self.initial = witness(new)[:5]
            self.check()
            os.fsync(self.parent_fd)
        except BaseException:
            self.close()
            raise

    def check(self, named=True):
        require(self.fd is not None and witness(os.fstat(self.fd))[:5] == self.initial,
                'held output directory object changed')
        if named:
            for path, fd, expected in self.ancestors:
                require(witness(os.fstat(fd))[:5] == expected
                        and witness(path.lstat())[:5] == expected,
                        'protected output ancestor object or binding changed')
            require(witness(os.fstat(self.parent_fd))[:5] == self.parents[0][1],
                    'held output parent changed')
            check_parents(self.parents)
            require(witness(os.stat(self.path.name, dir_fd=self.parent_fd,
                                    follow_symlinks=False))[:5] == self.initial,
                    'new output directory was renamed or substituted')

    def create_file(self, name, access=os.O_WRONLY, forensic=False):
        require(name in (OUTPUT, 'commands.json', 'conversion.json', 'failure.json'),
                'unsupported output basename')
        require(not forensic or name == 'failure.json', 'only failure evidence may survive a renamed namespace')
        self.check(named=not forensic)
        fd = os.open(name, access | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            value = os.fstat(fd)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                    and value.st_dev == os.fstat(self.fd).st_dev,
                    'new output is not an exclusive regular member')
            self.check(named=not forensic)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def check_file(self, name, fd):
        self.check()
        require(witness(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                == witness(os.fstat(fd)), 'held output member substituted')

    def sync(self, forensic=False):
        self.check(named=not forensic)
        os.fsync(self.fd)
        self.check(named=not forensic)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for _, fd, _ in reversed(self.ancestors):
            os.close(fd)
        self.ancestors.clear()
        self.parent_fd = None


class Held:
    def __init__(self, path, maximum, readonly_mount=False, executable=False):
        self.path = Path(path)
        self.parents = parents(self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            value = os.fstat(self.fd)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                    and 0 < value.st_size <= maximum, 'input is not bounded single-link regular data')
            require(not readonly_mount or os.fstatvfs(self.fd).f_flag & os.ST_RDONLY,
                    'raw input must be on an actual read-only mount')
            if executable:
                require(value.st_uid == 0 and value.st_mode & 0o7111 == 0o111
                        and not value.st_mode & 0o022
                        and os.pread(self.fd, 7, 0) == b'\x7fELF\x02\x01\x01',
                        'converter must be an actual root-protected x86-64 ELF without set-ID bits')
            self.initial = witness(value)
            fcntl.flock(self.fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.check()
        except BaseException:
            os.close(self.fd)
            raise

    def check(self):
        require(witness(os.fstat(self.fd)) == self.initial
                and witness(self.path.lstat()) == self.initial, 'held input changed')
        check_parents(self.parents)

    def hash(self, deadline=None):
        self.check()
        value, offset = hashlib.sha256(), 0
        while offset < self.initial[6]:
            if deadline is not None:
                require(time.monotonic() <= deadline, 'held hashing observation deadline exceeded')
            block = os.pread(self.fd, min(MIB, self.initial[6] - offset), offset)
            require(block, 'held input truncated')
            value.update(block)
            offset += len(block)
        require(not os.pread(self.fd, 1, offset), 'held input grew')
        self.check()
        return value.hexdigest()

    def close(self):
        os.close(self.fd)


def child_limits(maximum):
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))


def run(tool, arguments, inherited, maximum, timeout=1800):
    tool.check()
    args = ['/proc/self/fd/' + str(tool.fd), *map(str, arguments)]
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, pass_fds=(tool.fd, *inherited),
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'},
        preexec_fn=lambda: child_limits(maximum))
    result = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        for stream, name in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'converter observation deadline exceeded')
                for key, _ in selector.select(min(1, remaining)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    result[key.data].extend(block)
                    require(len(result[key.data]) <= 65536, 'converter diagnostic bound exceeded')
            require(child.wait(timeout=max(.01, deadline - time.monotonic())) == 0,
                    'converter refused: ' + result['stderr'].decode('utf-8', 'replace')[-2048:])
            tool.check()
            return {name: bytes(data).decode('utf-8', 'strict') for name, data in result.items()}
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()


def unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'duplicate JSON field')
        result[name] = value
    return result


def parse_info(data, size):
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: require(False, 'nonfinite converter JSON'))
    require(isinstance(value, dict) and value.get('format') == 'vhdx'
            and type(value.get('virtual-size')) is int and value['virtual-size'] == size
            and type(value.get('cluster-size')) is int and value['cluster-size'] == BLOCK
            and value.get('dirty-flag') is False
            and not any('backing' in key or 'parent' in key for key in value),
            'VHDX converter metadata differs from the closed dynamic profile')
    return value


def vhdx_geometry(fd, size):
    """Inspect bounded real metadata, not filenames or qemu JSON sector guesses."""
    require(os.pread(fd, 8, 0) == b'vhdxfile', 'VHDX identifier missing')
    region = os.pread(fd, 65536, 192*1024)
    require(len(region) == 65536 and region[:4] == b'regi'
            and struct.unpack_from('<II', region, 8) == (2, 0), 'unexpected VHDX region table')
    metadata_guid = uuid.UUID('8b7ca206-4790-4b9a-b8fe-575f050f886e').bytes_le
    bat_guid = uuid.UUID('2dc27766-f623-4200-9d64-115e9bfd4a08').bytes_le
    regions = {}
    length = os.fstat(fd).st_size
    for offset in (16, 48):
        kind, start, count, flags = struct.unpack_from('<16sQII', region, offset)
        # The pinned QEMU creator emits its two known regions with data_bits=0.
        require(kind in (metadata_guid, bat_guid) and kind not in regions and flags == 0
                and start >= MIB and start % MIB == 0 and count == MIB
                and start + count <= length, 'VHDX region is aliased, external or unsupported')
        regions[kind] = (start, count)
    require(regions[metadata_guid][0] != regions[bat_guid][0], 'overlapping VHDX metadata/BAT')
    start, count = regions[metadata_guid]
    data = os.pread(fd, count, start)
    require(len(data) == count and data[:8] == b'metadata'
            and struct.unpack_from('<HH', data, 8) == (0, 5) and not any(data[12:32]),
            'unsupported VHDX metadata inventory')
    expected = {
        uuid.UUID('caa16737-fa36-4d43-b3b6-33f0aa44e76b').bytes_le: ('parameters', 8),
        uuid.UUID('2fa54224-cd1b-4876-b211-5dbed83bf4b8').bytes_le: ('size', 8),
        uuid.UUID('beca12ab-b2e6-4523-93ef-c309e000c746').bytes_le: ('identity', 16),
        uuid.UUID('8141bf1d-a96f-4709-ba47-f233a8faab5f').bytes_le: ('logical', 4),
        uuid.UUID('cda348c7-445d-4471-9cc9-e9885251c556').bytes_le: ('physical', 4),
    }
    fields, spans = {}, []
    for offset in range(32, 32 + 5*32, 32):
        kind, begin, width, flags, reserved = struct.unpack_from('<16sIIII', data, offset)
        require(kind in expected and expected[kind][0] not in fields
                and width == expected[kind][1] and 65536 <= begin <= count-width
                and reserved == 0 and flags & ~7 == 0 and flags & 4,
                'unknown, duplicate, parent or malformed VHDX metadata')
        require(all(begin + width <= lo or begin >= hi for lo, hi in spans), 'overlapping metadata values')
        spans.append((begin, begin+width))
        fields[expected[kind][0]] = data[begin:begin+width]
    require(struct.unpack('<II', fields['parameters']) == (BLOCK, 0)
            and struct.unpack('<Q', fields['size'])[0] == size
            and struct.unpack('<I', fields['logical'])[0] == 512
            and struct.unpack('<I', fields['physical'])[0] == 512
            and any(fields['identity']), 'VHDX has a parent, fixed allocation or wrong geometry')
    return dict(virtual_bytes=size, block_bytes=BLOCK, logical_sector_bytes=512,
                physical_sector_bytes=512, dynamic=True, parent_present=False)


def write_json(directory, name, value, forensic=False):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(data) <= 65536, 'conversion record exceeded bound')
    fd = directory.create_file(name, forensic=forensic)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        directory.check(named=not forensic)
    finally:
        os.close(fd)
    directory.sync(forensic=forensic)


def _convert(source, directory, tool):
    """Held-data converter also exercised on tiny real qemu fixtures; no GPT claim."""
    require(MIB <= source.initial[6] <= MAX_RAW and source.initial[6] % 512 == 0,
            'raw conversion input must be sector-aligned bounded regular data')
    maximum = source.initial[6] + 128*MIB
    fd = directory.create_file(OUTPUT, access=os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = os.fstat(fd)
        inherited = (source.fd, fd)
        src, dst = '/proc/self/fd/' + str(source.fd), '/proc/self/fd/' + str(fd)
        logs = []
        for args in (['create', '-q', '-f', 'vhdx', '-o', OPTIONS, dst, str(source.initial[6])],
                     ['convert', '-q', '-n', '-f', 'raw', '-O', 'vhdx', '-m', '1', src, dst],
                     ['compare', '-q', '-f', 'raw', '-F', 'vhdx', src, dst]):
            directory.check_file(OUTPUT, fd)
            source.check()
            logs.append(run(tool, args, inherited, maximum))
            source.check()
            current = os.fstat(fd)
            require(current.st_nlink == 1 and current.st_dev == original.st_dev
                    and current.st_ino == original.st_ino and current.st_size <= maximum,
                    'new output substituted or grew beyond bound')
            directory.check_file(OUTPUT, fd)
        os.fsync(fd)
        info = run(tool, ['info', '--output=json', '-f', 'vhdx', dst], inherited, maximum, timeout=60)
        parse_info(info['stdout'], source.initial[6])
        geometry = vhdx_geometry(fd, source.initial[6])
        logs.append(info)
        directory.check_file(OUTPUT, fd)
        before = witness(os.fstat(fd))
        digest, offset = hashlib.sha256(), 0
        while offset < before[6]:
            block = os.pread(fd, min(MIB, before[6]-offset), offset)
            require(block, 'new VHDX truncated during held hashing')
            digest.update(block)
            offset += len(block)
        require(not os.pread(fd, 1, offset) and witness(os.fstat(fd)) == before,
                'new VHDX changed during held hashing')
        directory.check_file(OUTPUT, fd)
        directory.sync()
        return geometry, logs, dict(bytes=offset, sha256=digest.hexdigest())
    finally:
        os.close(fd)


def convert(raw, raw_sha256, destination, qemu, qemu_sha256):
    require(sys.platform == 'linux', 'conversion requires the isolated Linux build environment')
    pin(raw_sha256)
    pin(qemu_sha256)
    destination = Path(destination)
    require(destination.is_relative_to(Path('/mnt/luma-build/work')),
            'new staging output must be in the private D-backed ext4 work namespace; public export is separate')
    namespace = parents(destination)
    require(not os.path.lexists(destination), 'refusing an existing conversion output directory')
    source = Held(raw, MAX_RAW, readonly_mount=True)
    tool = None
    directory = None
    try:
        require(source.initial[6] == DESKTOP_BYTES, 'only exact desktop live-installer disk geometry is supported')
        require(source.hash() == raw_sha256, 'independent raw-image SHA256 differs')
        tool = Held(qemu, 64*MIB, executable=True)
        require(tool.hash() == qemu_sha256, 'independent actual converter ELF SHA256 differs')
        spec = importlib.util.spec_from_file_location('luma_hyperv_existing_geometry', Path(__file__).with_name('resume.py'))
        resume = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(resume)
        resume.verify_gpt(Path('/proc/self/fd/' + str(source.fd)), 'desktop')
        source.check()
        info = os.statvfs(destination.parent)
        require(info.f_bavail * info.f_frsize >= DESKTOP_BYTES + 128*MIB + 2*1024**3,
                'insufficient observed space for worst-case VHDX plus2GiB work headroom; no reservation claimed')
        check_parents(namespace)
        directory = OutputDirectory(destination)
        geometry, logs, output = _convert(source, directory, tool)
        require(source.hash() == raw_sha256 and tool.hash() == qemu_sha256,
                'raw or converter content changed across conversion')
        directory.check()
        check_parents(namespace)
        report = dict(schema_version=1, purpose='luma-hyperv-live-installer-v1', architecture='amd64',
            profile='V', media_kind='live-installer-disk', vm_generation=2,
            source_raw_bytes=DESKTOP_BYTES, source_raw_sha256=raw_sha256,
            converter_sha256=qemu_sha256, output_name=OUTPUT, output_bytes=output['bytes'],
            output_sha256=output['sha256'], geometry=geometry, raw_preserved=True,
            raw_vhdx_guest_bytes_compared=True, installed_desktop=False,
            vm_created=False, vm_started=False, boot_qualified=False, production_qualified=False,
            secure_boot_trust_established=False, vtpm_commissioned=False,
            host_settings_changed=False, physical_disk_opened=False, gate_closing=False)
        write_json(directory, 'commands.json', dict(schema_version=1, commands=logs))
        write_json(directory, 'conversion.json', report)
        directory.check()
        return report
    except BaseException as error:
        if directory is not None:
            write_json(directory, 'failure.json', dict(schema_version=1, status='conversion-failed',
                error_type=type(error).__name__, error=str(error)[:4096],
                failed_outputs_retained=True, vm_created=False, boot_qualified=False), forensic=True)
        raise
    finally:
        if tool is not None:
            tool.close()
        if directory is not None:
            directory.close()
        source.close()


class ExportDirectory:
    """Held existing public parent; no pathname can redirect a child write.

    Public/exFAT storage is untrusted staging, not custody. Other writers may
    delete or corrupt exports; readers must independently rehash them. Atomic
    O_EXCL file creation avoids the mkdir/reopen substitution problem. Namespace
    substitutions refuse success but cannot redirect effects into replacements.
    """
    def __init__(self, path, names):
        self.path, self.names, self.chain = Path(path), frozenset(names), []
        require(self.path.is_absolute() and str(self.path) == os.path.normpath(self.path)
                and len(self.path.parts) <= 32, 'canonical bounded export parent required')
        require(self.names and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}', name)
                                   for name in self.names), 'closed export basenames required')
        try:
            current = Path('/')
            for index, part in enumerate(self.path.parts):
                if index == 0:
                    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                else:
                    current /= part
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=self.chain[-1][1])
                value = witness(os.fstat(fd))[:5]
                self.chain.append((current, fd, value))
            self.fd = self.chain[-1][1]
            self.check()
            for name in self.names:
                require(not os.path.lexists('/proc/self/fd/' + str(self.fd) + '/' + name),
                        'refusing an existing export member')
        except BaseException:
            self.close()
            raise

    def check(self, named=True):
        for path, fd, expected in self.chain:
            require(witness(os.fstat(fd))[:5] == expected, 'held public export directory changed')
            if named:
                require(witness(path.lstat())[:5] == expected, 'public export namespace substituted')

    def create(self, name, forensic=False):
        require(name in self.names, 'unselected export basename refused')
        self.check(named=not forensic)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            value = os.fstat(fd)
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                    and value.st_dev == os.fstat(self.fd).st_dev, 'new export is not an exclusive regular member')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def check_file(self, name, fd):
        self.check()
        require(witness(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == witness(os.fstat(fd)),
                'public export member substituted')

    def close(self):
        for _, fd, _ in reversed(self.chain):
            os.close(fd)
        self.chain.clear()


def held_bytes(source, maximum):
    require(source.initial[6] <= maximum, 'record exceeds bound')
    source.check()
    data = os.pread(source.fd, maximum + 1, 0)
    require(len(data) == source.initial[6], 'held record length changed')
    source.check()
    return data


def closed_json(data):
    def pairs(values):
        record = {}
        for key, value in values:
            require(key not in record, 'duplicate JSON field')
            record[key] = value
        return record
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, 'nonfinite JSON refused'))


def validate_conversion(record, raw_sha256, vhdx_sha256):
    expected = dict(schema_version=1, purpose='luma-hyperv-live-installer-v1', architecture='amd64',
        profile='V', media_kind='live-installer-disk', vm_generation=2, source_raw_bytes=DESKTOP_BYTES,
        source_raw_sha256=raw_sha256, output_name=OUTPUT, output_sha256=vhdx_sha256,
        raw_preserved=True, raw_vhdx_guest_bytes_compared=True, installed_desktop=False,
        vm_created=False, vm_started=False, boot_qualified=False, production_qualified=False,
        secure_boot_trust_established=False, vtpm_commissioned=False, host_settings_changed=False,
        physical_disk_opened=False, gate_closing=False,
        geometry=dict(virtual_bytes=DESKTOP_BYTES, block_bytes=BLOCK, logical_sector_bytes=512,
                      physical_sector_bytes=512, dynamic=True, parent_present=False))
    require(type(record) is dict and set(record) == set(expected) | {'converter_sha256', 'output_bytes'},
            'closed conversion record required')
    for field, value in expected.items():
        # Python bool/int equality must not admit a claimed qualification or
        # geometry under a different JSON type.
        actual = record[field]
        require(type(actual) is type(value) and actual == value, 'conversion identity or qualification differs')
    geometry = record['geometry']
    require(set(geometry) == set(expected['geometry']) and all(type(geometry[key]) is type(value)
            for key, value in expected['geometry'].items()), 'conversion geometry types differ')
    pin(record['converter_sha256'])
    require(type(record['output_bytes']) is int and MIB <= record['output_bytes'] <= DESKTOP_BYTES + 128*MIB,
            'bounded converted VHDX length required')


def copy_export(source, directory, name, expected, deadline):
    fd = directory.create(name)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        offset, digest = 0, hashlib.sha256()
        while offset < source.initial[6]:
            require(time.monotonic() <= deadline, 'export copying observation deadline exceeded')
            source.check()
            directory.check_file(name, fd)
            block = os.pread(source.fd, min(MIB, source.initial[6] - offset), offset)
            require(block, 'held export source truncated')
            written = 0
            while written < len(block):
                count = os.pwrite(fd, block[written:], offset + written)
                require(count > 0, 'export write made no progress')
                written += count
            digest.update(block)
            offset += len(block)
        os.fsync(fd)
        require(digest.hexdigest() == expected and os.fstat(fd).st_size == offset,
                'export copy differs from independent pin')
        before, digest = witness(os.fstat(fd)), hashlib.sha256()
        offset = 0
        while offset < before[6]:
            require(time.monotonic() <= deadline, 'export readback observation deadline exceeded')
            block = os.pread(fd, min(MIB, before[6] - offset), offset)
            require(block, 'export truncated during independent readback')
            digest.update(block)
            offset += len(block)
        require(digest.hexdigest() == expected and witness(os.fstat(fd)) == before
                and not os.pread(fd, 1, offset), 'export full readback differs or changed')
        source.check()
        directory.check_file(name, fd)
        return fd, before
    except BaseException:
        os.close(fd)
        raise


def export_record(directory, name, record, forensic=False):
    data = (json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(data) <= 65536, 'export record exceeds bound')
    fd = directory.create(name, forensic=forensic)
    try:
        offset = 0
        while offset < len(data):
            count = os.pwrite(fd, data[offset:], offset)
            require(count > 0, 'export record write made no progress')
            offset += count
        os.fsync(fd)
        seal = witness(os.fstat(fd))
        require(os.pread(fd, len(data)+1, 0) == data and witness(os.fstat(fd)) == seal,
                'export record readback differs or changed')
        if not forensic:
            directory.check_file(name, fd)
        os.fsync(directory.fd)
        return fd, seal
    except BaseException:
        os.close(fd)
        raise


def export_verified(manifest, manifest_sha256, raw_sha256, vhdx_sha256, destination):
    """Copy independently pinned private conversion DATA to new public D files."""
    require(sys.platform == 'linux' and os.geteuid() == 0, 'isolated trusted-root Linux export required')
    # Local synchronous filesystem calls cannot be forcibly deadline-bounded.
    # Refuse once30minutes have been observed between calls; never call this a
    # hard I/O completion deadline or an authenticated authority session.
    deadline = time.monotonic() + 1800
    for value in (manifest_sha256, raw_sha256, vhdx_sha256):
        pin(value)
    manifest, destination = Path(manifest), Path(destination)
    require(all(path.is_absolute() and str(path) == os.path.normpath(path)
                for path in (manifest, destination)), 'canonical absolute export inputs required')
    require(manifest.name == 'conversion.json' and manifest.is_relative_to(PRIVATE_STAGE),
            'conversion must originate in private D-backed ext4 staging')
    require(destination.is_relative_to(PUBLIC_EXPORT) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.vhdx', destination.name),
            'new canonical Windows-readable D build VHDX target required')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}
    require(all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,159}', part)
                and not part.endswith(('.', ' ')) and part.split('.')[0].upper() not in reserved
                for part in destination.relative_to(PUBLIC_EXPORT).parts),
            'export components must be unambiguous ordinary Windows names')
    names = [destination.name + suffix for suffix in ('', '.conversion.json', '.export.json', '.failure.json')]
    metadata = source = directory = None
    outputs = []
    try:
        metadata = Held(manifest, 65536)
        source = Held(manifest.parent / OUTPUT, DESKTOP_BYTES + 128*MIB)
        for held in (metadata, source):
            require(held.initial[3] == 0 and not held.initial[2] & 0o077,
                    'private conversion input must be root-owned and nonpublic')
            for path, _ in held.parents:
                info = path.lstat()
                require(info.st_uid == 0 and not info.st_mode & 0o022, 'private conversion ancestor is writable')
            writable_ext4(held.fd)
        require(metadata.hash(deadline) == manifest_sha256, 'independent conversion record SHA256 differs')
        record = closed_json(held_bytes(metadata, 65536))
        validate_conversion(record, raw_sha256, vhdx_sha256)
        require(source.initial[6] == record['output_bytes'] and source.hash(deadline) == vhdx_sha256,
                'independently pinned private VHDX differs')
        require(vhdx_geometry(source.fd, DESKTOP_BYTES) == record['geometry'], 'held VHDX geometry differs')
        directory = ExportDirectory(destination.parent, names)
        space = os.fstatvfs(directory.fd)
        require(space.f_bavail * space.f_frsize >= source.initial[6] + 2*1024**3,
                'observed public export space lacks VHDX plus2GiB headroom; not a reservation')
        for name, held, digest in ((names[0], source, vhdx_sha256), (names[1], metadata, manifest_sha256)):
            fd, seal = copy_export(held, directory, name, digest, deadline)
            outputs.append((name, fd, seal))
        require(source.hash(deadline) == vhdx_sha256 and metadata.hash(deadline) == manifest_sha256,
                'private conversion inputs changed across export')
        receipt = dict(schema_version=1, purpose='luma-hyperv-public-export-v1', output_name=names[0],
            output_bytes=source.initial[6], output_sha256=vhdx_sha256,
            conversion_name=names[1], conversion_sha256=manifest_sha256,
            source_raw_sha256=raw_sha256, source_conversion_preserved=True,
            full_destination_readback=True, public_staging_untrusted=True,
            installed_desktop=False, vm_created=False, vm_started=False,
            boot_qualified=False, production_qualified=False, gate_closing=False)
        for name, fd, seal in outputs:
            directory.check_file(name, fd)
            require(witness(os.fstat(fd)) == seal, 'export member changed after readback')
        fd, seal = export_record(directory, names[2], receipt)
        outputs.append((names[2], fd, seal))
        for name, fd, seal in outputs:
            directory.check_file(name, fd)
            require(witness(os.fstat(fd)) == seal, 'export member changed across receipt publication')
        directory.check()
        require(time.monotonic() <= deadline, 'export publication observation deadline exceeded')
        return receipt
    except BaseException as error:
        if directory is not None:
            try:
                forensic_fd, _ = export_record(directory, names[3], dict(schema_version=1, status='export-failed',
                    error_type=type(error).__name__, error=str(error)[:4096],
                    failed_outputs_retained=True, vm_created=False, boot_qualified=False), forensic=True)
                os.close(forensic_fd)
            except BaseException as forensic_error:
                error.add_note('Forensic record could not be created exclusively: ' + str(forensic_error)[:1024])
        raise
    finally:
        for _, fd, _ in reversed(outputs):
            os.close(fd)
        if directory is not None:
            directory.close()
        for held in (source, metadata):
            if held is not None:
                held.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'export':
        parser = argparse.ArgumentParser(description='Export verified conversion data to new public D files, never deploy a VM.')
        parser.add_argument('--manifest', type=Path, required=True)
        parser.add_argument('--manifest-sha256', required=True)
        parser.add_argument('--raw-sha256', required=True)
        parser.add_argument('--vhdx-sha256', required=True)
        parser.add_argument('--output', type=Path, required=True)
        args = parser.parse_args(sys.argv[2:])
        print(json.dumps(export_verified(args.manifest, args.manifest_sha256, args.raw_sha256,
                                         args.vhdx_sha256, args.output), sort_keys=True))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--raw-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qemu-img', type=Path, required=True)
    parser.add_argument('--qemu-img-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(convert(args.raw, args.raw_sha256, args.output, args.qemu_img,
                             args.qemu_img_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
