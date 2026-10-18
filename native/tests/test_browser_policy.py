"""Image WebKit pins use genuine ELF bytes; fixtures do not execute WebKit."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


IMAGE = Path(__file__).resolve().parents[1] / 'image'
sys.path.insert(0, str(IMAGE))
try:
    SPEC = importlib.util.spec_from_file_location('luma_browser_policy_tests', IMAGE / 'browser_policy.py')
    policy = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(policy)
finally:
    sys.path.pop(0)


class BrowserPolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'image policy fixtures require isolated root runner')
        temporary = tempfile.TemporaryDirectory(prefix='luma-browser-policy-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        self.status = self.root / 'var/lib/dpkg/status'
        self.status.parent.mkdir(parents=True)
        self.status.write_text('Package: libwebkit2gtk-4.1-0\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.48.3-0ubuntu0.24.04.1\n\n')
        self.status.chmod(0o644)
        directory = self.root / 'usr/lib/x86_64-linux-gnu'
        directory.mkdir(parents=True)
        self.library = directory / 'libwebkit2gtk-4.1.so.0.18.3'
        shutil.copyfile(Path('/usr/bin/true').resolve(strict=True), self.library)
        self.library.chmod(0o644)
        self.alias = directory / 'libwebkit2gtk-4.1.so.0'
        self.alias.symlink_to(self.library.name)

    def test_manifest_pins_exact_package_runtime_and_actual_elf_bytes(self):
        encoded = policy.canonical_manifest(self.root)
        self.assertEqual(encoded, policy.canonical_manifest(self.root))
        value = json.loads(encoded)
        self.assertEqual(value['runtime_version'], [2, 48, 3])
        self.assertEqual(value['library']['path'], '/usr/lib/x86_64-linux-gnu/' + self.library.name)
        self.assertEqual(value['library']['bytes'], self.library.stat().st_size)
        self.assertFalse(value['native_qualified'])

    def test_rejects_external_alias_stub_hardlink_and_writable_library(self):
        for target in (str(self.library), '../x86_64-linux-gnu/' + self.library.name,
                       '/usr/bin/true', 'libwebkit2gtk-4.1.so.0.invalid'):
            self.alias.unlink()
            self.alias.symlink_to(target)
            with self.assertRaises((ValueError, OSError)):
                policy.canonical_manifest(self.root)
        self.alias.unlink()
        self.alias.symlink_to(self.library.name)
        original = self.library.read_bytes()
        self.library.write_bytes(b'not a shared ELF library')
        with self.assertRaises(ValueError):
            policy.canonical_manifest(self.root)
        self.library.write_bytes(original)
        duplicate = self.library.parent / 'duplicate'
        os.link(self.library, duplicate)
        with self.assertRaises(ValueError):
            policy.canonical_manifest(self.root)
        duplicate.unlink()
        self.library.chmod(0o666)
        with self.assertRaises(ValueError):
            policy.canonical_manifest(self.root)

    def test_rejects_ambiguous_uninstalled_or_mismatched_runtime_metadata(self):
        original = self.status.read_text()
        for data in (original + original, original.replace('amd64', 'arm64'),
                     original.replace('install ok installed', 'deinstall ok config-files'),
                     original.replace('2.48.3-0ubuntu0.24.04.1', '3.0.0'),
                     original.replace('2.48.3-0ubuntu0.24.04.1', 'unknown')):
            self.status.write_text(data)
            with self.assertRaises(ValueError):
                policy.canonical_manifest(self.root)


if __name__ == '__main__':
    unittest.main()
