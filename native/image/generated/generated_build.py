#!/usr/bin/env python3
"""Fixed bounded C99-subset compiler and tests. Every compile/run is inside KVM."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import struct
import time

BASE = Path('/usr/share/luma-os/generated')
RUNNER = Path('/usr/libexec/luma-os/generated_build.py')
LANGUAGE = 'c99-freestanding-tcc-v1'
DEPENDENCIES = ['luma-syscall-v1', 'tinycc-libtcc1-0.9.27+git20200814.62c30a4a-1']
VERSION = '0.9.27+git20200814.62c30a4a-1'
CONTRACT = {'schema_version': 1, 'language': LANGUAGE, 'compiler_version': VERSION,
            'source_max_bytes': 16384, 'compiler_executable_max_bytes': 32768,
            'executable_max_bytes': 36864, 'elf_hardening': 'static-elf-stack-v1',
            'test_max_count': 2, 'stream_max_bytes': 2048,
            'compile_timeout_ms': 5000, 'test_timeout_ms': 1000,
            'total_timeout_ms': 15000, 'memory_mib': 128,
            'compiler_package_sha256': '8c8617f69cdbd8a9efb6ff20a1930d577a4348f41c53bbaa02932c2101c8c1f1',
            'compiler_library_package_sha256': '92b0128468d4fb0749efc317da319cddd89ab1507dad55a9daaecbf62614f36c'}
PINNED_TOOLCHAIN = {
    'relink/libtcc.a': '99487d6c78619ec6a9003641d938e5c59f2342b006d31619f8a056084f51dd11',
    'libtcc1.a': '66cffad205235f5c0ca72e028b574476a031b43dad7b13656461093f38bcff93',
    'relink/libtcc.h': 'de4930a8f312241f269ad26f07f8fd1aa6d119fe89212d9e89c516c12cc0885c',
    'relink/copyright': 'cbc67ed9530ac30b60e382b02968efc5a7de2895f50cd7c51e6c70811a8df115'}
FILE_NAMES = {'compiler-init': 2*1024*1024, 'compiler-init.c': 128*1024,
              'compiler-base.cpio': 4*1024*1024, 'test-init': 2*1024*1024,
              'test-base.cpio': 4*1024*1024, 'luma.h': 8192,
              'freestanding_runtime.c': 8192, 'libtcc1.a': 128*1024,
              'relink/compiler-init.o': 256*1024, 'relink/libtcc.a': 1024*1024,
              'relink/libtcc.h': 32768, 'relink/copyright': 65536,
              'relink/guest_init.c': 128*1024, 'relink/relink.sh': 8192,
              'build-runner.py': 128*1024, 'prepare-build.py': 128*1024}
SOURCE_FILES = {
    'tcc_0.9.27+git20200814.62c30a4a-1.dsc': (2274, '3d211ea8e260e6b846c9a085ea43229c48b20871be7a7ad8f520b2d345587cfd'),
    'tcc_0.9.27+git20200814.62c30a4a.orig.tar.bz2': (708943, 'd63c113bcdd657f51c8ee197a0b0a24203603313e19a52b5f678d40ab7f5df35'),
    'tcc_0.9.27+git20200814.62c30a4a-1.debian.tar.xz': (15044, '27036dd5f67b6ce3b8212080d1d6e55b1f7b2e54a23d0f2a4af38090a8d75716')}
FILE_NAMES.update({'relink/source/' + name: maximum for name, (maximum, _) in SOURCE_FILES.items()})
FILE_NAMES.update({'relink/source-provenance.json': 8192, 'relink/LGPL-2': 65536,
                   'relink/LGPL-2.1': 65536, 'relink/GPL-2': 65536})


def load_runtime():
    path = Path('/usr/libexec/luma-os/generated_runtime.py')
    # This import is an installed immutable executable asset, never a request path.
    for item in (path, *path.parents):
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('mutable generated runtime import')
    spec = importlib.util.spec_from_file_location('luma_generated_runtime_fixed', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unhex(value, maximum):
    if not isinstance(value, str) or len(value) > maximum * 2 or len(value) % 2 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('noncanonical or oversized hex')
    return bytes.fromhex(value)


def source_profile(source):
    if not source or len(source) > 16384 or any(b not in (9, 10, 13) and not 32 <= b <= 126 for b in source):
        raise ValueError('source must be bounded ASCII C99-subset text')
    if b'\\\n' in source or b'\\\r\n' in source or b'%:' in source or b'??' in source:
        raise ValueError('alternate preprocessing/spliced source is outside this profile')
    for line in source.splitlines():
        if b'#' in line and line.strip() != b'#include "luma.h"':
            raise ValueError('only the declared luma.h include is supported')
    # Strip literals/comments before checking compiler-extension tokens. No
    # extension adds an undeclared dependency or assembler-file input.
    tokens = re.sub(rb'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', b' ', source, flags=re.S)
    if re.search(rb'\b(?:asm|__asm|__asm__|__attribute__|__builtin[A-Za-z0-9_]*)\b', tokens):
        raise ValueError('assembler/compiler extension is outside this C99 subset')


def validate_request(value):
    if not isinstance(value, dict) or list(value) != ['schema_version', 'language', 'declared_dependencies', 'source_hex', 'tests']:
        raise ValueError('unknown/noncanonical build request schema')
    if type(value['schema_version']) is not int or value['schema_version'] != 2 or value['language'] != LANGUAGE or value['declared_dependencies'] != DEPENDENCIES:
        raise ValueError('unsupported language or declared dependencies')
    source = unhex(value['source_hex'], 16384)
    source_profile(source)
    tests = value['tests']
    if not isinstance(tests, list) or not 1 <= len(tests) <= 2:
        raise ValueError('one or two explicit test oracles are required')
    for test in tests:
        if not isinstance(test, dict) or list(test) != ['stdin_hex', 'expected_exit', 'expected_stdout_hex', 'expected_stderr_hex']:
            raise ValueError('unknown/noncanonical test schema')
        if type(test['expected_exit']) is not int or not 0 <= test['expected_exit'] <= 255:
            raise ValueError('explicit finite exit oracle required')
        for key in ('stdin_hex', 'expected_stdout_hex', 'expected_stderr_hex'):
            unhex(test[key], 2048)
    return source


def parse_request(raw, runtime):
    if not raw or len(raw) > 65536:
        raise ValueError('bounded build request required')
    value = runtime.closed_json(raw)
    validate_request(value)
    if json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode() != raw:
        raise ValueError('exact canonical build request required')
    return value


def capture(runtime):
    old, kernel, _ = runtime.capture_runtime()
    raw = runtime.read_fixed(BASE / 'build-manifest.json', 16384)
    value = runtime.closed_json(raw)
    if not isinstance(value, dict) or set(value) != set(CONTRACT) | {'runtime_manifest_sha256', 'files'} or any(value[k] != v or type(value[k]) is not type(v) for k, v in CONTRACT.items()):
        raise ValueError('unsupported compiler appliance contract')
    if value['runtime_manifest_sha256'] != runtime.sha(old) or not isinstance(value['files'], dict) or set(value['files']) != set(FILE_NAMES):
        raise ValueError('compiler appliance closure differs from immutable manifest')
    files = {}
    for name, maximum in FILE_NAMES.items():
        data = runtime.read_fixed(BASE / name, maximum)
        if value['files'][name] != runtime.sha(data):
            raise ValueError('compiler appliance closure changed')
        files[name] = data
    if any(value['files'][name] != digest for name, digest in PINNED_TOOLCHAIN.items()):
        raise ValueError('compiler package assets differ from reviewed pinned package bytes')
    if runtime.read_fixed(RUNNER, 128*1024) != files['build-runner.py']:
        raise ValueError('compiler runner identity differs')
    # Every initramfs entry is reconstructed from the pinned closure, preventing
    # an unrecorded toolchain/dependency file from entering either appliance.
    compiler = runtime.cpio([
        ('init', files['compiler-init'], stat.S_IFREG | 0o755, 0, 0, 0, 0),
        ('dev', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1),
        ('work', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('compiler', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('compiler/libtcc1.a', files['libtcc1.a'], stat.S_IFREG | 0o444, 0, 0, 0, 0),
        ('include', b'', stat.S_IFDIR | 0o555, 0, 0, 0, 0),
        ('include/luma.h', files['luma.h'], stat.S_IFREG | 0o444, 0, 0, 0, 0),
        ('runtime.c', files['freestanding_runtime.c'], stat.S_IFREG | 0o444, 0, 0, 0, 0)])
    test = runtime.cpio([('init', files['test-init'], stat.S_IFREG | 0o755, 0, 0, 0, 0),
                         ('dev', b'', stat.S_IFDIR | 0o755, 0, 0, 0, 0),
                         ('dev/console', b'', stat.S_IFCHR | 0o600, 0, 0, 5, 1)])
    if compiler != files['compiler-base.cpio'] or test != files['test-base.cpio']:
        raise ValueError('unexpected compiler/test initramfs members')
    return raw, kernel, files


def run_vm(runtime, kernel, initrd, deadline):
    descriptors = []
    process = None
    try:
        descriptors.append(runtime.sealed('luma-generated-kernel', kernel))
        descriptors.append(runtime.sealed('luma-generated-initrd', initrd))
        process = subprocess.Popen(runtime.qemu_command(*descriptors), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=descriptors,
                                   close_fds=True, start_new_session=True, env={'PATH': '/usr/bin', 'LC_ALL': 'C'},
                                   preexec_fn=runtime.drop_qemu(runtime.qemu_identity(), os.getpid()))
        pidfd = os.pidfd_open(process.pid)
        buffers = [bytearray(), bytearray()]
        try:
            with selectors.DefaultSelector() as selector:
                for i, stream in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, i)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError('combined compile/test KVM deadline exceeded; no completion receipt')
                    for event, _ in selector.select(.05):
                        data = os.read(event.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(event.fileobj)
                        else:
                            buffers[event.data].extend(data)
                            if len(buffers[event.data]) > 196608:
                                raise ValueError('bounded guest transcript exceeded')
                if process.wait(timeout=max(.01, deadline - time.monotonic())):
                    raise ValueError('KVM completion uncertain')
            return bytes(buffers[0])
        finally:
            if process.poll() is None:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                process.wait(timeout=3)
            os.close(pidfd)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill(); process.wait(timeout=3)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        for descriptor in descriptors:
            os.close(descriptor)


def compiler_result(runtime, raw):
    prefix = b'LUMA_COMPILER_RESULT_V1 '
    lines = [line for line in raw.replace(b'\r\n', b'\n').split(b'\n') if line.startswith(prefix)]
    if len(lines) != 1 or b'LUMA_COMPILER_FAILURE_V1' in raw:
        raise ValueError('compiler completion missing/ambiguous')
    value = runtime.closed_json(lines[0][len(prefix):])
    if not isinstance(value, dict) or set(value) != {'status', 'value', 'stdout_hex', 'stderr_hex', 'executable_hex'}:
        raise ValueError('unknown compiler completion schema')
    if value['status'] not in ('exit', 'signal', 'timeout', 'output_limit') or type(value['value']) is not int or not 0 <= value['value'] <= 255 or (value['status'] == 'signal' and not 1 <= value['value'] <= 64):
        raise ValueError('invalid compiler status')
    for key in ('stdout_hex', 'stderr_hex'):
        unhex(value[key], 2048)
    executable = unhex(value['executable_hex'], 32768)
    if bool(executable) != (value['status'] == 'exit' and value['value'] == 0):
        raise ValueError('compiler success lacks actual executable bytes')
    return value, executable


def harden_elf(raw, runtime):
    """Explicit build-only data transform; original compiler bytes are retained.

    TinyCC omits GNU_STACK and emits empty LOAD records. Move only the program
    header table, drop truly empty LOADs and append one RW/nonexec stack record.
    All executable/data/section bytes stay intact, and the unchanged v1 strict
    validator must accept the complete transformed artifact before any test.
    """
    if not 64 <= len(raw) <= 32768:
        raise ValueError('compiler artifact exceeds bounded hardening input')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    if header[0][:7] != b'\x7fELF\x02\x01\x01' or header[1:4] != (2, 62, 1) or header[8:10] != (64, 56):
        raise ValueError('unsupported compiler ELF header')
    offset, count = header[5], header[10]
    if not 1 <= count <= 63 or offset < 64 or offset + count*56 > len(raw):
        raise ValueError('unsupported compiler ELF program table')
    records = []
    for index in range(count):
        data = raw[offset + index*56:offset + (index+1)*56]
        kind, flags, file_offset, address, physical, size, memory, alignment = struct.unpack('<IIQQQQQQ', data)
        if kind not in (0, 1, 4, 7, 0x6474e552, 0x6474e553):
            raise ValueError('unknown/dynamic/PHDR/stack compiler segment')
        if flags & ~7 or flags & 3 == 3 or size > memory or file_offset + size > len(raw):
            raise ValueError('invalid/WX compiler segment')
        if kind == 1 and size == memory == 0:
            continue
        records.append(data)
    records.append(struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    new_offset = (len(raw) + 7) & ~7
    result = bytearray(raw + b'\0'*(new_offset - len(raw)) + b''.join(records))
    if len(result) > 36864:
        raise ValueError('hardened runnable artifact exceeds its exact bound')
    struct.pack_into('<Q', result, 32, new_offset)
    struct.pack_into('<H', result, 56, len(records))
    runtime.validate_static_elf(result)
    return bytes(result)


def test_result(runtime, raw):
    prefix = b'LUMA_GENERATED_RESULT_V1 '
    lines = [line for line in raw.replace(b'\r\n', b'\n').split(b'\n') if line.startswith(prefix)]
    if len(lines) != 1 or b'LUMA_GENERATED_FAILURE_V1' in raw:
        raise ValueError('test completion missing/ambiguous')
    value = runtime.closed_json(lines[0][len(prefix):])
    if not isinstance(value, dict) or set(value) != {'execution_status', 'execution_value', 'stdout_hex', 'stderr_hex'}:
        raise ValueError('unknown bounded test result')
    if value['execution_status'] not in ('exit', 'signal', 'timeout', 'output_limit') or type(value['execution_value']) is not int or not 0 <= value['execution_value'] <= 255:
        raise ValueError('invalid test status')
    if value['execution_status'] == 'signal' and not 1 <= value['execution_value'] <= 64:
        raise ValueError('invalid test signal/limit result')
    for key in ('stdout_hex', 'stderr_hex'):
        unhex(value[key], 2048)
    return value


def run(request, runtime):
    if os.geteuid() != 0:
        raise ValueError('governed root acquisition helper required')
    source = validate_request(request)
    raw, kernel, files = capture(runtime)
    deadline = time.monotonic() + 15
    initrd = files['compiler-base.cpio'] + runtime.cpio([('source.c', source, stat.S_IFREG | 0o444, 0, 0, 0, 0)])
    compiled, original = compiler_result(runtime, run_vm(runtime, kernel, initrd, deadline))
    compiled['executable_sha256'] = runtime.sha(original)
    executable = b''
    results = []
    artifact_status = 'not_produced'
    hardening = 'not_attempted'
    if original:
        try:
            executable = harden_elf(original, runtime)
            artifact_status = 'validated_static_amd64'
            hardening = CONTRACT['elf_hardening']
        except ValueError:
            # A real successful compiler exit is not a qualified runnable ELF.
            # Preserve bytes/digest and compiler output; run no unvalidated code.
            artifact_status = 'rejected_static_elf'
            hardening = 'rejected'
    for index, test in enumerate(request['tests']):
        if artifact_status != 'validated_static_amd64':
            results.append({'index': index, 'status': 'not_run', 'reason': 'compile_or_static_validation_failed'})
            continue
        input_bytes = unhex(test['stdin_hex'], 2048)
        payload = runtime.build_payload_initrd(files['test-base.cpio'], executable, input_bytes)
        observed = test_result(runtime, run_vm(runtime, kernel, payload, deadline))
        # The dedicated test guest kills/drains at 2KiB; this check refuses a
        # changed guest, never truncates a successful completion to fit a receipt.
        for key in ('stdout_hex', 'stderr_hex'):
            unhex(observed[key], 2048)
        passed = observed['execution_status'] == 'exit' and observed['execution_value'] == test['expected_exit'] and observed['stdout_hex'] == test['expected_stdout_hex'] and observed['stderr_hex'] == test['expected_stderr_hex']
        results.append({'index': index, 'status': 'passed' if passed else 'failed', **observed})
    final, _, _ = capture(runtime)
    if final != raw:
        raise ValueError('compiler closure changed during execution')
    return {'schema_version': 2, 'runtime_sha256': runtime.sha(raw),
            'request_sha256': runtime.sha(json.dumps(request, separators=(',', ':')).encode()),
            'source_hex': request['source_hex'], 'language': LANGUAGE, 'declared_dependencies': DEPENDENCIES,
            'toolchain_files': runtime.closed_json(raw)['files'], 'compiler': compiled,
            'executable_hex': executable.hex(), 'executable_sha256': runtime.sha(executable),
            'elf_hardening': hardening, 'artifact_status': artifact_status,
            'test_oracles': request['tests'], 'tests': results,
            'all_tests_passed': artifact_status == 'validated_static_amd64' and all(test['status'] == 'passed' for test in results)}


def main():
    import sys
    if sys.argv[1:] != ['--request-fd', '0']:
        raise ValueError('only sealed build request invocation supported')
    runtime = load_runtime()
    raw = runtime.read_sealed(0, 'luma-generated-request', 65536)
    result = run(parse_request(raw, runtime), runtime)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    if len(encoded) >= 256*1024:
        raise ValueError('whole compiler receipt exceeds exact admission bound')
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import sys
        sys.stderr.write('luma-generated-build: refused or uncertain\n')
        raise SystemExit(1)
