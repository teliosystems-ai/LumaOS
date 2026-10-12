"""Closed ELF/receipt/resource regressions, not real KVM qualification."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / 'native/image/generated'
SPEC = importlib.util.spec_from_file_location('generated_runtime', ASSETS / 'generated_runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
REQUEST_SPEC = importlib.util.spec_from_file_location('generated_request', ASSETS / 'prepare_request.py')
request = importlib.util.module_from_spec(REQUEST_SPEC)
REQUEST_SPEC.loader.exec_module(request)


def elf():
    data = bytearray(256)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                     2, 62, 1, 0x4000c0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
    struct.pack_into('<IIQQQQQQ', data, 120, 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    return data


class GeneratedRuntimeTests(unittest.TestCase):
    def test_bounded_static_elf_structural_acceptance_does_not_execute_code(self):
        result = runtime.validate_static_elf(bytes(elf()))
        self.assertEqual(result, {'entry': 0x4000c0, 'load_bytes': 256})

    def test_foreign_dynamic_interpreted_executable_stack_and_wx_refuse(self):
        for label, offset, format_string, value in (
                ('machine', 18, '<H', 183), ('type', 16, '<H', 3),
                ('dynamic', 64, '<I', 2), ('interpreter', 64, '<I', 3),
                ('wx', 68, '<I', 7), ('stack', 124, '<I', 7),
                ('entry', 24, '<Q', 0x600000), ('memory', 104, '<Q', 64 * 1024 * 1024),
                ('phrange', 32, '<Q', 240), ('unknown', 64, '<I', 0x77777777)):
            with self.subTest(label=label):
                changed = elf()
                struct.pack_into(format_string, changed, offset, value)
                with self.assertRaises(ValueError):
                    runtime.validate_static_elf(bytes(changed))
        for data in (b'', bytes(63), bytes(1048577)):
            with self.assertRaises(ValueError):
                runtime.validate_static_elf(data)

    def test_kernel_qemu_command_has_no_tcg_disk_network_or_host_mount_fallback(self):
        command = runtime.qemu_command(8, 9)
        self.assertEqual(command[command.index('-accel') + 1], 'kvm')
        self.assertEqual(command[command.index('-nic') + 1], 'none')
        for denied in ('-drive', '-blockdev', '-fsdev', '-virtfs', '-netdev', '-device', '-enable-kvm', 'tcg'):
            self.assertNotIn(denied, command)
        self.assertIn('/proc/self/fd/8', command)
        self.assertIn('/proc/self/fd/9', command)
        self.assertEqual(command[command.index('-m') + 1], '128')

    def test_guest_output_is_hex_not_executable_or_serialized_authority(self):
        payload = {'execution_status': 'exit', 'execution_value': 0,
                   'stdout_hex': b'LUMA_GENERATED_RESULT_V1 {"forged":true}'.hex(), 'stderr_hex': ''}
        wire = b'boot noise\r\nLUMA_GENERATED_RESULT_V1 ' + json.dumps(payload).encode() + b'\r\n'
        self.assertEqual(runtime.parse_guest(wire), payload)
        for invalid in (wire + wire, wire + b'LUMA_GENERATED_FAILURE_V1\n',
                        wire.replace(b'"execution_value": 0', b'"execution_value": true'),
                        wire.replace(b'"stderr_hex": ""', b'"stderr_hex": "GG"'),
                        wire.replace(b'"stderr_hex": ""', b'"stderr_hex": "f"'),
                        wire.replace(b'"stderr_hex": ""', b'"stderr_hex": "' + b'00' * 32769 + b'"'),
                        b'LUMA_GENERATED_RESULT_V1 {"execution_status":"exit","execution_status":"exit"}\n'):
            with self.assertRaises(ValueError):
                runtime.parse_guest(invalid)

    def test_fully_sealed_request_names_and_sizes_are_mandatory(self):
        descriptor = os.memfd_create('luma-generated-executable', os.MFD_ALLOW_SEALING)
        try:
            os.write(descriptor, bytes(elf()))
            with self.assertRaises(ValueError):
                runtime.read_sealed(descriptor, 'luma-generated-executable', 1048576)
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, runtime.SEALS)
            self.assertEqual(runtime.read_sealed(descriptor, 'luma-generated-executable', 1048576), bytes(elf()))
            with self.assertRaises(ValueError):
                runtime.read_sealed(descriptor, 'luma-generated-input', 1048576)
            with self.assertRaises(ValueError):
                runtime.read_sealed(descriptor, 'luma-generated-executable', 128)
        finally:
            os.close(descriptor)

    def test_payload_archive_binds_only_task_and_stdin_after_fixed_base(self):
        base = runtime.cpio([('init', b'fixed trusted fixture', stat.S_IFREG | 0o755, 0, 0, 0, 0)])
        result = runtime.build_payload_initrd(base, bytes(elf()), b'input')
        self.assertTrue(result.startswith(base))
        self.assertEqual(result[len(base):], runtime.cpio([
            ('task', bytes(elf()), stat.S_IFREG | 0o555, 0, 0, 0, 0),
            ('input', b'input', stat.S_IFREG | 0o400, 1000, 1000, 0, 0)]))
        with self.assertRaises(ValueError):
            runtime.build_payload_initrd(base, bytes(elf()), bytes(65537))

    def test_guest_preexec_has_exact_credential_capability_deadline_and_seccomp_guards(self):
        source = (ASSETS / 'guest_init.c').read_text()
        for actual in ('setgroups(0, NULL)', 'setgid(1000)', 'setuid(1000)',
                       'PR_CAPBSET_DROP', 'SYS_capget', 'PR_SET_NO_NEW_PRIVS',
                       'SECCOMP_RET_KILL_PROCESS', 'AUDIT_ARCH_X86_64',
                       'FD_CLOEXEC', 'RLIMIT_AS', 'RLIMIT_CPU', 'WALL_MS 3000'):
            self.assertIn(actual, source)
        for forbidden in ('ALLOW(socket)', 'ALLOW(open)', 'ALLOW(openat)', 'ALLOW(clone)',
                          'ALLOW(fork)', 'ALLOW(mount)', 'ALLOW(ioctl)', 'ALLOW(ptrace)', 'ALLOW(execve)'):
            self.assertNotIn(forbidden, source)
        runner = (ASSETS / 'generated_runtime.py').read_text()
        for actual in ('os.pidfd_open', 'signal.pidfd_send_signal', 'process.wait(timeout=5)',
                       'os.setgroups([kvm_group])', 'library.capget', 'library.prctl(24',
                       'library.prctl(39', 'os.getppid() != parent', 'library.prctl(1, signal.SIGKILL'):
            self.assertIn(actual, runner)
        self.assertNotIn('os.fchown', runner)

    def test_fixed_qemu_profile_denies_authority_and_other_host_resources(self):
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-generated-qemu').read_text()
        for denied in ('deny capability,', 'deny network,', 'deny mount,', 'deny ptrace,'):
            self.assertIn(denied, profile)
        self.assertIn('/dev/kvm rw,', profile)
        for forbidden in ('/dev/tpm', '/dev/dri', '/dev/sd', '/var/lib/', 'network inet', 'ux,', 'tcg'):
            self.assertNotIn(forbidden, profile)

    def test_request_preparation_is_closed_canonical_data_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable, stdin = directory / 'static-task', directory / 'input'
            executable.write_bytes(bytes(elf()))
            stdin.write_bytes(b'\0untrusted input\xff')
            with patch.object(request.runtime, 'run', side_effect=AssertionError('must never execute')):
                raw = request.prepare(executable, stdin)
                self.assertEqual(raw, b'{"schema_version":1,"executable_hex":"' + bytes(elf()).hex().encode()
                                 + b'","stdin_hex":"' + stdin.read_bytes().hex().encode() + b'"}')
                self.assertNotIn(b'\n', raw)
                self.assertEqual(raw, json.dumps(json.loads(raw), separators=(',', ':')).encode('ascii'))
                self.assertEqual(json.loads(request.prepare(executable))['stdin_hex'], '')
                self.assertLessEqual(len(raw), request.MAX_REQUEST)
            source = (ASSETS / 'prepare_request.py').read_text()
            for forbidden in ('subprocess', 'runtime.run(', 'execve', 'kernel_sha256', 'custody'):
                self.assertNotIn(forbidden, source)
            package = (ASSETS / 'package_runtime.py').read_text()
            self.assertIn("'usr/libexec/luma-os/prepare_generated_request.py'", package)

    def test_request_capture_rejects_links_nonregular_and_size_or_elf_relaxation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable, stdin = directory / 'task', directory / 'input'
            executable.write_bytes(bytes(elf()))
            stdin.write_bytes(bytes(65537))
            with self.assertRaises(ValueError):
                request.prepare(executable, stdin)
            executable.write_bytes(b'not ELF')
            with self.assertRaises(ValueError):
                request.prepare(executable)
            executable.write_bytes(bytes(elf()) + bytes(1048577))
            with self.assertRaises(ValueError):
                request.prepare(executable)
            executable.write_bytes(bytes(elf()))
            link = directory / 'symlink'
            link.symlink_to(executable)
            hard = directory / 'hardlink'
            os.link(executable, hard)
            fifo = directory / 'fifo'
            os.mkfifo(fifo)
            for path in (link, hard, fifo, directory):
                with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                    request.snapshot(path, 1048576)
            parent_link = directory / 'parent-link'
            parent_link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                request.snapshot(parent_link / 'task', 1048576)

    def test_request_capture_fences_changed_content_and_replaced_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            parent = directory / 'namespace'
            parent.mkdir()
            executable = parent / 'task'
            executable.write_bytes(bytes(elf()))
            original_read = request.os.read
            changed = False
            def mutate(descriptor, count):
                nonlocal changed
                data = original_read(descriptor, count)
                if data and not changed:
                    changed = True
                    executable.write_bytes(bytes(elf()) + b'change')
                return data
            with patch.object(request.os, 'read', side_effect=mutate), self.assertRaises(ValueError):
                request.snapshot(executable, 1048576)
            executable.write_bytes(bytes(elf()))
            changed = False
            def replace_namespace(descriptor, count):
                nonlocal changed
                data = original_read(descriptor, count)
                if data and not changed:
                    changed = True
                    parent.rename(directory / 'detached')
                    parent.mkdir()
                    executable.write_bytes(bytes(elf()))
                return data
            with patch.object(request.os, 'read', side_effect=replace_namespace), self.assertRaises(ValueError):
                request.snapshot(executable, 1048576)

    def test_maximum_request_is_bounded_and_no_qualification_is_inferred(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable, stdin = directory / 'task', directory / 'input'
            executable.write_bytes(bytes(elf()) + bytes(1048576 - len(elf())))
            stdin.write_bytes(bytes(65536))
            raw = request.prepare(executable, stdin)
            self.assertLessEqual(len(raw), request.MAX_REQUEST)
            self.assertEqual(set(json.loads(raw)), {'schema_version', 'executable_hex', 'stdin_hex'})
        corpus = (ROOT / 'native/tests/generated_kvm_integration.py').read_text()
        self.assertIn("'host_apparmor_enforced':False", corpus)
        self.assertIn("'governed_resource_admission_tested':False", corpus)
        self.assertIn("'installed_image_qualified':False", corpus)
        self.assertIn("'purpose':'diagnostic-not-qualification'", corpus)


if __name__ == '__main__':
    unittest.main()
