"""Actual hardened ELF/helper tests, not loaded policy or graphical acceptance."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
         '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIE', '-pie',
         '-Wl,-z,relro,-z,now,-z,noexecstack']


class WorkspaceLauncherTests(unittest.TestCase):
    def test_actual_hardened_fixed_elf_and_pure_protocol_fixture(self):
        compiler = shutil.which('gcc')
        self.assertIsNotNone(compiler, 'actual Linux GCC fixture lane required')
        storage = Path(os.environ['LUMA_STORAGE_TEST_ROOT']).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='workspace-launcher-', dir=storage) as temporary:
            directory = Path(temporary)
            for source, name in [('native/image/workspace_launcher.c', 'launcher'),
                                 ('native/tests/workspace_launcher_fixture.c', 'fixture')]:
                target = directory/name
                subprocess.run([compiler, *FLAGS, str(ROOT/source), '-o', str(target)],
                               check=True, capture_output=True, timeout=30)
                data = target.read_bytes()
                self.assertEqual(data[:7], b'\x7fELF\x02\x01\x01')
                self.assertEqual(int.from_bytes(data[18:20], 'little'), 62)
            refused = subprocess.run([str(directory/'launcher'), 'unwanted'],
                                     capture_output=True, timeout=5)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(refused.stdout, b'')
            self.assertIn(b'No sandbox bypass or authority fallback', refused.stderr)
            fixture = subprocess.run([str(directory/'fixture')], capture_output=True,
                                     check=True, timeout=5)
            result = json.loads(fixture.stdout)
            self.assertGreaterEqual(result['assertions'], 70)
            self.assertTrue(result['actual_c_helpers'])
            for key in ('profile_loaded', 'gui_started', 'namespace_created'):
                self.assertIs(result[key], False)

    def test_profile_attaches_only_fixed_launcher_and_retains_no_global_bypass(self):
        text = (ROOT/'native/image/overlay/etc/apparmor.d/luma-workspace').read_text()
        self.assertIn('abi <abi/4.0>,', text)
        self.assertIn('profile luma-workspace /usr/libexec/luma-os/luma-workspace-launch flags=(unconfined)', text)
        self.assertIn('userns,', text)
        for forbidden in ('/usr/bin/python', '/usr/bin/bwrap', 'sysctl', 'capability,',
                          'WEBKIT_DISABLE_SANDBOX', 'ux,'):
            self.assertNotIn(forbidden, text)
        source = (ROOT/'native/image/workspace_launcher.c').read_text()
        self.assertIn('"/usr/bin/python3", "-I", SCRIPT, NULL', source)
        self.assertIn('argc != 1', source)
        self.assertIn('actual_label()', source)
        self.assertIn('getresuid', source)
        self.assertIn('getresgid', source)
        self.assertIn('clearenv()', source)
        self.assertIn('close_range(3, ~0U, 0)', source)
        self.assertNotIn('PR_SET_NO_NEW_PRIVS', source)


if __name__ == '__main__':
    unittest.main()
