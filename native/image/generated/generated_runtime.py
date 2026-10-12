#!/usr/bin/python3
"""Fixed real-KVM generated ELF runner; invocation is descriptor-only.

The caller must independently maintain the current governed/resource lease.
Receipts are observations, never grant/custody/lease authority. No generated
executable is loaded or executed by the host operating system.
"""
import ctypes
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import struct
import subprocess
import time

BASE = Path('/usr/share/luma-os/generated')
RUNNER = Path('/usr/libexec/luma-os/generated_runtime.py')
QEMU = Path('/usr/bin/qemu-system-x86_64')
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
CONTRACT = {'architecture': 'x86_64', 'acceleration': 'kvm', 'memory_mib': 128,
            'timeout_ms': 15000, 'guest_timeout_ms': 3000, 'executable_max_bytes': 1048576,
            'input_max_bytes': 65536, 'stdout_max_bytes': 32768, 'stderr_max_bytes': 32768}
HASH_FIELDS = ('kernel_sha256', 'base_initrd_sha256', 'qemu_sha256', 'guest_init_sha256',
               'guest_init_source_sha256', 'runner_sha256')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def closed_json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(path, maximum):
    for ancestor in path.parents:
        metadata = ancestor.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('redirected/writable/non-root immutable runtime ancestor')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o6022 or before.st_size > maximum:
            raise ValueError('runtime input is not immutable root-owned bounded regular bytes')
        data = file.read(maximum + 1)
        if len(data) != before.st_size or identity(before) != identity(os.fstat(file.fileno())) or identity(before) != identity(os.stat(path, follow_symlinks=False)):
            raise ValueError('runtime input changed during capture')
    return data


def read_sealed(descriptor, name, maximum):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 0 or before.st_size > maximum or before.st_size < 0:
        raise ValueError('generated request requires bounded anonymous regular memfd')
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != SEALS or os.readlink('/proc/self/fd/' + str(descriptor)) != '/memfd:' + name + ' (deleted)':
        raise ValueError('generated request requires exact fully sealed input memfd')
    data = os.pread(descriptor, maximum + 1, 0)
    if len(data) != before.st_size or identity(before) != identity(os.fstat(descriptor)):
        raise ValueError('sealed input observation changed')
    return data


def validate_static_elf(data):
    if not 64 <= len(data) <= CONTRACT['executable_max_bytes']:
        raise ValueError('static ELF size is outside the supported bound')
    values = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    ident, kind, machine, version, entry, offset, section_offset, flags, header_size, size, count, section_size, section_count, strings = values
    if ident[:7] != b'\x7fELF\x02\x01\x01' or ident[7] not in (0, 3) or any(ident[8:]) or kind != 2 or machine != 62 or version != 1 or flags or header_size != 64:
        raise ValueError('requires closed static x86_64 ET_EXEC ELF')
    if size != 56 or not 1 <= count <= 64 or offset < 64 or offset + size * count > len(data):
        raise ValueError('invalid bounded program-header table')
    if section_count:
        if section_size != 64 or section_count > 4096 or section_offset < 64 or section_offset + section_size * section_count > len(data) or strings >= section_count:
            raise ValueError('invalid bounded section-header table')
    elif section_offset or strings:
        raise ValueError('unsupported extended section table')
    loads, executable, total, stack, tls = [], False, 0, 0, 0
    for index in range(count):
        kind, access, file_offset, address, physical, files, memory, alignment = struct.unpack_from('<IIQQQQQQ', data, offset + size * index)
        if kind not in (0, 1, 4, 6, 7, 0x6474e551, 0x6474e552, 0x6474e553):
            raise ValueError('dynamic/interpreted/unknown ELF segment')
        if access & ~7 or files > memory or file_offset + files > len(data):
            raise ValueError('invalid segment flags/file range')
        if kind == 0x6474e551:
            stack += 1
            if access & 1 or stack > 1:
                raise ValueError('executable or duplicate guest stack')
        if kind == 7:
            tls += 1
            if tls > 1 or memory > 1024 * 1024:
                raise ValueError('unsupported TLS segment')
        if kind != 1:
            continue
        if access & 3 == 3 or not memory or address < 0x10000 or address + memory >= 0x0000800000000000:
            raise ValueError('writable executable or invalid guest load address')
        if alignment not in (0, 1) and (alignment & (alignment - 1) or alignment > 2 * 1024 * 1024 or address % alignment != file_offset % alignment):
            raise ValueError('invalid guest segment alignment')
        rounded = (address & ~4095, (address + memory + 4095) & ~4095)
        if any(rounded[0] < previous[1] and previous[0] < rounded[1] for previous in loads):
            raise ValueError('overlapping guest load pages')
        loads.append(rounded)
        total += memory
        if access & 1 and address <= entry < address + files:
            executable = True
    if not executable or not loads or total > 32 * 1024 * 1024 or stack != 1:
        raise ValueError('missing finite executable entry/nonexecutable stack declaration')
    return {'entry': entry, 'load_bytes': total}


def cpio(entries):
    """Deterministic newc, only fixed appliance namespace entries."""
    result = bytearray()
    for inode, (name, data, mode, uid, gid, major, minor) in enumerate([*entries, ('TRAILER!!!', b'', 0, 0, 0, 0, 0)], 1):
        encoded = name.encode('ascii') + b'\0'
        fields = (inode, mode, uid, gid, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0)
        result.extend(b'070701' + ''.join('%08x' % field for field in fields).encode())
        result.extend(encoded)
        result.extend(b'\0' * (-len(result) % 4))
        result.extend(data)
        result.extend(b'\0' * (-len(result) % 4))
    result.extend(b'\0' * (-len(result) % 512))
    return bytes(result)


def build_payload_initrd(base, executable, input_bytes):
    validate_static_elf(executable)
    if len(input_bytes) > CONTRACT['input_max_bytes']:
        raise ValueError('generated stdin exceeds fixed bound')
    return base + cpio([('task', executable, stat.S_IFREG | 0o555, 0, 0, 0, 0),
                        ('input', input_bytes, stat.S_IFREG | 0o400, 1000, 1000, 0, 0)])


def capture_runtime():
    raw = read_fixed(BASE / 'manifest.json', 8192)
    manifest = closed_json(raw)
    if not isinstance(manifest, dict) or set(manifest) != {'schema_version', *CONTRACT, *HASH_FIELDS} or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1:
        raise ValueError('unknown generated runtime manifest')
    if any(type(manifest[key]) is not type(value) or manifest[key] != value for key, value in CONTRACT.items()):
        raise ValueError('relaxed generated-runtime resource/isolation contract')
    if any(not isinstance(manifest[key], str) or len(manifest[key]) != 64 or any(character not in '0123456789abcdef' for character in manifest[key]) for key in HASH_FIELDS):
        raise ValueError('invalid immutable runtime hash')
    paths = {'kernel_sha256': (BASE / 'kernel', 32 * 1024 * 1024),
             'base_initrd_sha256': (BASE / 'base-initrd.cpio', 8 * 1024 * 1024),
             'guest_init_sha256': (BASE / 'guest-init', 8 * 1024 * 1024),
             'guest_init_source_sha256': (BASE / 'guest-init.c', 128 * 1024),
             'runner_sha256': (RUNNER, 128 * 1024), 'qemu_sha256': (QEMU, 128 * 1024 * 1024)}
    captured = {}
    for key, (path, bound) in paths.items():
        data = read_fixed(path, bound)
        if sha(data) != manifest[key]:
            raise ValueError('immutable generated runtime bytes differ: ' + key)
        captured[key] = data
    expected = cpio([('init', captured['guest_init_sha256'], stat.S_IFREG | 0o755, 0, 0, 0, 0),
                     ('dev', b'', stat.S_IFDIR | 0o755, 0, 0, 0, 0),
                     ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1)])
    if captured['base_initrd_sha256'] != expected:
        raise ValueError('base initrd contains anything outside fixed guest appliance')
    return raw, captured['kernel_sha256'], expected


def sealed(name, data):
    descriptor = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:offset + 65536])
        # The sealed root-owned inode is readable after the exact UID988 drop;
        # no CAP_CHOWN is needed or added to the acquisition helper. It has no
        # directory name and other processes cannot cross the confined peer.
        os.fchmod(descriptor, 0o444)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def qemu_command(kernel_fd, initrd_fd):
    return [str(QEMU), '-no-user-config', '-nodefaults', '-machine', 'q35', '-accel', 'kvm',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-cpu', 'qemu64', '-smp', '1', '-m', '128', '-display', 'none', '-monitor', 'none',
            '-nic', 'none', '-parallel', 'none', '-serial', 'stdio', '-no-reboot',
            '-kernel', '/proc/self/fd/' + str(kernel_fd), '-initrd', '/proc/self/fd/' + str(initrd_fd),
            '-append', 'console=ttyS0,115200 quiet loglevel=0 panic=-1 rdinit=/init nokaslr']


def qemu_identity():
    device = os.stat('/dev/kvm', follow_symlinks=False)
    group = grp.getgrnam('kvm').gr_gid
    if not stat.S_ISCHR(device.st_mode) or (os.major(device.st_rdev), os.minor(device.st_rdev)) != (10, 232) or device.st_uid != 0 or device.st_gid != group or device.st_mode & 0o777 != 0o660:
        raise ValueError('requires exact root:kvm mode0660 character10:232 device')
    return group


def drop_qemu(kvm_group, parent):
    def apply():
        library = ctypes.CDLL(None, use_errno=True)
        if library.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            os._exit(120)
        for capability in range(64):
            available = library.prctl(23, capability, 0, 0, 0)
            if available < 0:
                if ctypes.get_errno() != 22:
                    os._exit(123)
            elif available and library.prctl(24, capability, 0, 0, 0):
                os._exit(124)
        os.setgroups([kvm_group])
        os.setgid(988)
        os.setuid(988)
        header = (ctypes.c_uint32 * 2)(0x20080522, 0)
        data = (ctypes.c_uint32 * 6)()
        if library.capset(ctypes.byref(header), ctypes.byref(data)) or library.prctl(38, 1, 0, 0, 0) or library.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            os._exit(121)
        if library.capget(ctypes.byref(header), ctypes.byref(data)) or any(data) or library.prctl(39, 0, 0, 0, 0) != 1 or library.prctl(47, 4, 0, 0, 0):
            os._exit(125)
        for capability in range(64):
            bounding = library.prctl(23, capability, 0, 0, 0)
            if bounding > 0 or (bounding < 0 and ctypes.get_errno() != 22):
                os._exit(126)
        if os.geteuid() != 988 or os.getegid() != 988 or os.getgroups() != [kvm_group]:
            os._exit(122)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        os.umask(0o077)
    return apply


def parse_guest(data):
    prefix = b'LUMA_GENERATED_RESULT_V1 '
    lines = [line for line in data.replace(b'\r\n', b'\n').split(b'\n') if line.startswith(prefix)]
    if len(lines) != 1 or b'LUMA_GENERATED_FAILURE_V1' in data:
        raise ValueError('missing/ambiguous failed guest completion')
    result = closed_json(lines[0][len(prefix):])
    if not isinstance(result, dict) or set(result) != {'execution_status', 'execution_value', 'stdout_hex', 'stderr_hex'}:
        raise ValueError('unknown guest completion schema')
    if result['execution_status'] not in ('exit', 'signal') or type(result['execution_value']) is not int or not 0 <= result['execution_value'] <= (255 if result['execution_status'] == 'exit' else 64) or (result['execution_status'] == 'signal' and result['execution_value'] == 0):
        raise ValueError('invalid guest exit/signal result')
    for key, bound in (('stdout_hex', 32768), ('stderr_hex', 32768)):
        value = result[key]
        if not isinstance(value, str) or len(value) > bound * 2 or len(value) % 2 or any(character not in '0123456789abcdef' for character in value):
            raise ValueError('invalid/oversized guest output')
    return result


def run(executable, input_bytes):
    if os.geteuid() != 0:
        raise ValueError('fixed parent must execute in governed root acquisition worker')
    validate_static_elf(executable)
    raw, kernel, base = capture_runtime()
    kvm_group = qemu_identity()
    kernel_fd, initrd_fd = -1, -1
    process = None
    try:
        kernel_fd = sealed('luma-generated-kernel', kernel)
        initrd_fd = sealed('luma-generated-initrd', build_payload_initrd(base, executable, input_bytes))
        process = subprocess.Popen(qemu_command(kernel_fd, initrd_fd), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(kernel_fd, initrd_fd), close_fds=True, start_new_session=True,
                                   env={'PATH': '/usr/bin', 'LC_ALL': 'C'}, preexec_fn=drop_qemu(kvm_group, os.getpid()))
        pidfd = os.pidfd_open(process.pid)
        outputs = [bytearray(), bytearray()]
        deadline = time.monotonic() + 15
        try:
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('fixed KVM execution deadline expired; no receipt published')
                    for event, _ in selector.select(min(remaining, .1)):
                        block = os.read(event.fileobj.fileno(), 32768)
                        if not block:
                            selector.unregister(event.fileobj)
                            continue
                        outputs[event.data].extend(block)
                        if len(outputs[event.data]) > 256 * 1024:
                            raise ValueError('guest/QEMU transcript bound exceeded')
                status = process.wait(timeout=max(.01, deadline - time.monotonic()))
            if status != 0:
                raise ValueError('KVM process did not complete cleanly')
            result = parse_guest(bytes(outputs[0]))
        finally:
            if process.poll() is None:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                process.wait(timeout=5)
            os.close(pidfd)
        # A changing immutable runtime cannot lend a receipt to the old inputs.
        final, _, _ = capture_runtime()
        if final != raw:
            raise ValueError('runtime identity changed during KVM execution')
        return {'schema_version': 1, **result, 'runtime_sha256': sha(raw),
                'executable_sha256': sha(executable), 'input_sha256': sha(input_bytes)}
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        for descriptor in (kernel_fd, initrd_fd):
            if descriptor >= 0:
                os.close(descriptor)


def main():
    import sys
    if sys.argv[1:] != ['--executable-fd', '0', '--input-fd', '3']:
        raise ValueError('only exact sealed descriptor invocation is supported')
    executable = read_sealed(0, 'luma-generated-executable', 1048576)
    input_bytes = read_sealed(3, 'luma-generated-input', 65536)
    encoded = (json.dumps(run(executable, input_bytes), separators=(',', ':'), sort_keys=True) + '\n').encode()
    if len(encoded) > 256 * 1024:
        raise ValueError('receipt exceeded fixed output bound')
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Unvalidated executable/stdin, peer content and private paths must not
        # leak into diagnostics. Failure is not an executable completion receipt.
        import sys
        sys.stderr.write('luma-generated-runtime: execution refused or uncertain\n')
        raise SystemExit(1)
