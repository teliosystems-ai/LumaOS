import importlib.util
import json
from pathlib import Path
import signal
import struct
import unittest

ASSETS = Path(__file__).resolve().parents[1] / 'image/generated'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ASSETS / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


build = load('build_contract_tests', 'generated_build.py')
runtime = load('build_runtime_tests', 'generated_runtime.py')


def request():
    return {'schema_version': 2, 'language': build.LANGUAGE,
            'declared_dependencies': build.DEPENDENCIES,
            'source_hex': b'#include "luma.h"\nint main(void){return 0;}\n'.hex(),
            'tests': [{'stdin_hex': '', 'expected_exit': 0,
                       'expected_stdout_hex': '', 'expected_stderr_hex': ''}]}


class GeneratedBuildTests(unittest.TestCase):
    @staticmethod
    def compiler_elf():
        raw = bytearray(512)
        struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01' + b'\0'*9,
                         2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0x400000, 512, 512, 4096)
        struct.pack_into('<IIQQQQQQ', raw, 120, 1, 6, 512, 0x600200, 0x600200, 0, 0, 4096)
        return bytes(raw)

    def test_hardening_retains_verbatim_compiler_artifact_and_changes_only_table_header_fields(self):
        raw = self.compiler_elf()
        with self.assertRaises(ValueError):
            runtime.validate_static_elf(raw)
        actual = build.harden_elf(raw, runtime)
        runtime.validate_static_elf(actual)
        for at in range(len(raw)):
            if at not in range(32, 40) and at not in range(56, 58):
                self.assertEqual(actual[at], raw[at])
        self.assertEqual(struct.unpack_from('<Q', actual, 32)[0], len(raw))
        bss = bytearray(raw); struct.pack_into('<Q', bss, 160, 1)
        self.assertEqual(struct.unpack_from('<H', build.harden_elf(bss, runtime), 56)[0], 3)
        for kind in (2, 3, 6, 0x6474e551, 99):
            changed = bytearray(raw); struct.pack_into('<I', changed, 64, kind)
            with self.assertRaises(ValueError):
                build.harden_elf(changed, runtime)
        changed = bytearray(raw); struct.pack_into('<I', changed, 68, 7)
        with self.assertRaises(ValueError):
            build.harden_elf(changed, runtime)
        changed = bytearray(raw); struct.pack_into('<Q', changed, 136, 0x400200); struct.pack_into('<Q', changed, 160, 4096)
        with self.assertRaises(ValueError):
            build.harden_elf(changed, runtime)

    def test_closed_canonical_request_and_exact_dependencies(self):
        value = request()
        encoded = json.dumps(value, separators=(',', ':')).encode()
        self.assertEqual(build.parse_request(encoded, runtime), value)
        for changed in (encoded + b'\n', encoded.replace(b'"schema_version":2', b'"schema_version":true'),
                        encoded.replace(b'"schema_version":2', b'"schema_version":2,"schema_version":2')):
            with self.assertRaises(ValueError):
                build.parse_request(changed, runtime)
        for key, replacement in [('language', 'python'), ('declared_dependencies', ['libc']),
                                 ('flags', ['-run']), ('tests', []), ('source_hex', 'AA')]:
            changed = request(); changed[key] = replacement
            with self.assertRaises(ValueError):
                build.validate_request(changed)

    def test_source_subset_has_no_hidden_include_or_assembler_dependencies(self):
        for source in (b'#include </etc/shadow>', b'#define X 1', b'%:include "x"',
                       b'??=include "x"', b'#include \\\n"luma.h"', b'__asm__("hlt");',
                       b'__builtin_alloca(4)', b'asm("hlt");', b'\x00'):
            with self.assertRaises(ValueError):
                build.source_profile(source)
        build.source_profile(b'/* asm documentation */ int main(void){char *a="__asm__";return a[0];}')

    def test_actual_compiler_status_does_not_imply_a_test_pass(self):
        value = {'status': 'exit', 'value': 1, 'stdout_hex': '', 'stderr_hex': b'error'.hex(), 'executable_hex': ''}
        raw = b'LUMA_COMPILER_RESULT_V1 ' + json.dumps(value).encode() + b'\n'
        observed, executable = build.compiler_result(runtime, raw)
        self.assertEqual(observed['value'], 1)
        self.assertEqual(executable, b'')
        for changed in (raw + raw, raw + b'LUMA_COMPILER_FAILURE_V1', raw.replace(b'"value": 1', b'"value": 0')):
            with self.assertRaises(ValueError):
                build.compiler_result(runtime, changed)

    def test_buffered_output_limit_is_not_an_exit_or_success(self):
        value = {'execution_status': 'output_limit', 'execution_value': 0,
                 'stdout_hex': '41'*2048, 'stderr_hex': ''}
        raw = b'LUMA_GENERATED_RESULT_V1 ' + json.dumps(value).encode() + b'\n'
        observed = build.test_result(runtime, raw)
        self.assertEqual(observed['execution_status'], 'output_limit')
        self.assertEqual(observed['execution_value'], 0)
        value['stdout_hex'] += '41'
        with self.assertRaises(ValueError):
            build.test_result(runtime, b'LUMA_GENERATED_RESULT_V1 ' + json.dumps(value).encode())
        value['stdout_hex'] = ''; value['execution_status'] = 'signal'
        with self.assertRaises(ValueError):
            build.test_result(runtime, b'LUMA_GENERATED_RESULT_V1 ' + json.dumps(value).encode())

    def test_complete_guest_closure_and_corresponding_source_pins(self):
        self.assertEqual(len(build.FILE_NAMES), 23)
        for name, (size, digest) in build.SOURCE_FILES.items():
            self.assertIn('relink/source/' + name, build.FILE_NAMES)
            self.assertEqual(build.FILE_NAMES['relink/source/' + name], size)
            self.assertEqual(len(digest), 64)
        source = (ASSETS / 'compiler_init.c').read_text()
        self.assertIn('if (compiler_filter())', source)
        self.assertLess(source.index('if (compiler_filter())'), source.index('TCCState *state'))
        self.assertNotIn('ALLOW(execve', source)
        self.assertNotIn('ALLOW(clone', source)
        self.assertNotIn('ALLOW(socket', source)
        self.assertIn('getgroups(0, NULL) != 0', source)


if __name__ == '__main__':
    unittest.main()
