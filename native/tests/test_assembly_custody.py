"""Public domain-composition regressions; not signatures or custody evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import assembly_custody
import production_release


@unittest.skipUnless(os.name == 'posix', 'Linux public-file inventory checks')
class AssemblyCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.share = self.root / 'usr/share/luma-os'
        (self.share / 'skills').mkdir(parents=True)
        (self.share / 'models').mkdir()
        self.os_root = assembly_custody.public.SPKI + bytes([1]) * 32
        self.os_leaf = bytes([2]) * 32
        self.values = {'production-release-root.pub': b'fixture OS root public bytes'}
        self.report = {'root_der': self.os_root, 'release_public': b'fixture OS leaf public bytes',
                       'pcr_public': b'fixture PCR public bytes',
                       'signed_trust': {'trust': {'keys': [{'public_key_hex': self.os_leaf.hex()}]}}}
        for name, data in [('production-release-root.pub', self.values['production-release-root.pub']),
                           ('release.pub', self.report['release_public']),
                           ('admin-pcr-public.pem', self.report['pcr_public'])]:
            (self.share / name).write_bytes(data)
        self.skill = {'trust': {'environment': 'production', 'root_sha256': '3' * 64,
                               'keys': [{'public_key_hex': (bytes([4]) * 32).hex()}]}}
        self.model = {'bundle': {'environment': 'production',
                                'keys': [{'public_key': base64.b64encode(bytes([6]) * 32).decode()}]}}
        (self.share / 'model-roots.json').write_text(json.dumps(
            {'roots': [{'public_key': base64.b64encode(bytes([5]) * 32).decode()}]}))
        self.write_groups()
        authority = patch.object(production_release, 'load_inputs', return_value=(self.values, self.report))
        authority.start()
        self.addCleanup(authority.stop)

    def write_groups(self):
        (self.share / 'skills/initial-trust.json').write_text(json.dumps(self.skill))
        (self.share / 'models/initial-trust.json').write_text(json.dumps(self.model))

    def check(self):
        return assembly_custody.recheck_public_domains(self.root, self.root)

    def test_distinct_preverified_public_groups_do_not_activate(self):
        report = self.check()
        self.assertEqual(report['domains'], ['models', 'os-release', 'skills'])
        self.assertTrue(report['keys_are_distinct'])
        self.assertFalse(report['activated'])

    def test_second_packaging_adapter_cannot_replace_os_or_pcr_bytes(self):
        for name in ('production-release-root.pub', 'release.pub', 'admin-pcr-public.pem'):
            path = self.share / name
            saved = path.read_bytes()
            path.write_bytes(b'other public custody bytes')
            with self.assertRaises(ValueError):
                self.check()
            path.write_bytes(saved)

    def test_root_leaf_and_foreign_domain_key_reuse_refuse(self):
        self.skill['trust']['root_sha256'] = hashlib.sha256(self.os_root).hexdigest()
        self.write_groups()
        with self.assertRaises(ValueError):
            self.check()
        self.skill['trust']['root_sha256'] = '3' * 64
        for raw in (self.os_leaf, bytes([4]) * 32, bytes([1]) * 32):
            self.model['bundle']['keys'][0]['public_key'] = base64.b64encode(raw).decode()
            self.write_groups()
            with self.assertRaises(ValueError):
                self.check()

    def test_laboratory_group_never_substitutes_for_production(self):
        for group, key in ((self.skill, 'trust'), (self.model, 'bundle')):
            group[key]['environment'] = 'lab'
            self.write_groups()
            with self.assertRaises(ValueError):
                self.check()
            group[key]['environment'] = 'production'

    def test_raw_model_key_encoding_is_exact(self):
        expected = assembly_custody.public.SPKI + bytes([7]) * 32
        encoded = base64.b64encode(bytes([7]) * 32).decode()
        self.assertEqual(assembly_custody.raw_model_key(encoded), expected)
        for invalid in (None, encoded + '\n', encoded[:-1], base64.b64encode(bytes(31)).decode()):
            with self.assertRaises((ValueError, TypeError)):
                assembly_custody.raw_model_key(invalid)


if __name__ == '__main__':
    unittest.main()
