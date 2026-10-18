"""Image manifest policy tests using copied genuine system ELF, never executed.

Fixture package metadata is isolated data, not evidence LibreOffice is installed
or qualified. The real image hook must fingerprint its actual package tree.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_office_policy_tests', ROOT / 'native/image/office_policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class OfficePolicyTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'image policy fixtures require the isolated root test runner')
        self.temporary = tempfile.TemporaryDirectory(prefix='luma-office-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        source = Path('/usr/bin/true').resolve(strict=True)
        self.assertTrue(source.read_bytes().startswith(b'\x7fELF\x02\x01\x01'))
        for name in policy.FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, path)
            path.chmod(0o644)
        status = self.root / 'var/lib/dpkg/status'
        status.parent.mkdir(parents=True)
        status.write_text(''.join(f'Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0+isolated-test\n\n' for name in policy.PACKAGES))
        status.chmod(0o644)

    def test_deterministic_actual_byte_and_package_tuple_manifest(self):
        first = policy.canonical_manifest(self.root)
        self.assertEqual(first, policy.canonical_manifest(self.root))
        value = json.loads(first)
        self.assertEqual([item['name'] for item in value['packages']], list(policy.PACKAGES))
        self.assertEqual(value['profile'], 'libreoffice-document-html-pdf-v1')
        self.assertEqual(value['memory_bytes'], 1024**3)
        self.assertEqual(value['tasks'], 32)
        self.assertFalse(value['native_qualified'])
        for item in value['files']:
            self.assertEqual(item['bytes'], (self.root / item['path'].lstrip('/')).stat().st_size)

    def test_refuses_stub_alias_hardlink_permissions_and_size_before_hash(self):
        path = self.root / policy.FILES[0]
        original = path.read_bytes()
        path.write_bytes(b'not an ELF adapter executable')
        with self.assertRaises(ValueError):
            policy.manifest(self.root)
        path.write_bytes(original)
        other = self.root / 'linked'
        os.link(path, other)
        with self.assertRaises(ValueError):
            policy.manifest(self.root)
        other.unlink()
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            policy.manifest(self.root)
        path.chmod(0o644)
        path.unlink()
        path.symlink_to(Path('/usr/bin/true').resolve())
        with self.assertRaises(ValueError):
            policy.manifest(self.root)
        path.unlink()
        with path.open('wb') as stream:
            stream.truncate(policy.MAX_FILE + 1)
        with self.assertRaises(ValueError):
            policy.manifest(self.root)

    def test_refuses_missing_ambiguous_or_uninstalled_package_metadata(self):
        path = self.root / 'var/lib/dpkg/status'
        original = path.read_text()
        for changed in (original.replace('install ok installed', 'deinstall ok config-files', 1),
                        original + original, original.replace('Version: 1.0+isolated-test', 'Version: unknown', 1),
                        original.replace('Architecture: amd64', 'Architecture: arm64', 1),
                        original.split('\n\n', 1)[1]):
            path.write_text(changed)
            with self.assertRaises(ValueError):
                policy.manifest(self.root)
        path.write_text(original)
        self.assertEqual(len(policy.manifest(self.root)['files']), 3)


if __name__ == '__main__':
    unittest.main()
