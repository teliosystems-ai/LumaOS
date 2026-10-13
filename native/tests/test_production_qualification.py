"""Actual disposable certification signatures with no fabricated QA authority."""
import base64
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import production_qualification as qualification
from test_model_inputs import Fixture


class ProductionQualificationTests(unittest.TestCase):
    def test_actual_external_record_signature_roundtrip_and_exact_report_pins(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-qualification-test-') as path:
            base = Path(path); fixture = Fixture(base)
            prefix, profile = fixture.pack(production=True)
            cert_public = fixture.keys.key('certifier')
            fixture.bundle['keys'].append({'environment': 'production', 'key_id': 'Certifier',
                'not_before': '2026-10-03T00:00:00Z', 'not_after': '2026-10-30T00:00:00Z',
                'public_key': base64.b64encode(qualification.public.public_der(cert_public)[12:]).decode(),
                'public_key_encoding': 'raw-ed25519-base64', 'purposes': ['model-pack-execution-certification', 'model-pack-interactive-certification'],
                'role': 'model-pack-certification-signer', 'revoked_at': None, 'revocation_reason': None})
            fixture.bundle['keys'].sort(key=lambda k: k['key_id']); fixture.refresh()
            report = base / 'external-report'; report.write_bytes(b'disposable transport fixture, not native QA or certification')
            descriptor = {'schema_version': 1, 'level': 'execution', 'installation_sha256': '12' * 32,
                'release_manifest_sha256': '34' * 32, 'model_profile_sha256': qualification.public.sha(qualification.model.canonical(profile)),
                'runtime_tuple_sha256': profile['runtime_tuple_sha256'], 'test_report_sha256': qualification.public.sha(report.read_bytes()),
                'hardware': {'cpu_vendor': 'GenuineIntel', 'cpu_family': 6, 'cpu_model': 123, 'cpu_stepping': 1,
                    'features': ['avx', 'avx2'], 'logical_cpus': 4, 'total_memory_bytes': 16 * 1024**3}}
            observer = base / 'observer.json'; observer.write_bytes(qualification.production.canonical({'schema_version': 1,
                'evidence': descriptor, 'evidence_sha256': qualification.public.sha(qualification.production.canonical(descriptor)),
                'certified': False, 'authority_returned': False}))
            request = base / 'request'
            result = qualification.prepare(observer, report, fixture.inputs, profile['profile_id'], 'Certifier', request)
            self.assertFalse(result['certified']); response = base / 'response'; response.mkdir()
            record = (request / 'record.json').read_bytes()
            (response / 'record.sig').write_bytes(bytes.fromhex(fixture.keys.sign('certifier', record)))
            (response / 'response.json').write_bytes(qualification.production.canonical({'schema_version': 1, 'request_sha256': result['request_sha256']}))
            output = base / 'transfer.json'; receipt = qualification.assemble(request, response, output)
            self.assertTrue(receipt['external_public_signature_verified']); self.assertFalse(receipt['qa_verified'])
            package = qualification.model.document(output.read_bytes())
            self.assertEqual(package['package']['evidence'], descriptor)
            self.assertIsNone(package['expected_previous_sha256'])
            with self.assertRaises(FileExistsError): qualification.assemble(request, response, output)
            for mutation in ('signature', 'request'):
                signature = (response / 'record.sig').read_bytes()
                metadata = (response / 'response.json').read_bytes()
                if mutation == 'signature': (response / 'record.sig').write_bytes(bytes(64))
                else: (response / 'response.json').write_bytes(qualification.production.canonical({'schema_version': 1, 'request_sha256': 'ff' * 32}))
                with self.assertRaises(ValueError): qualification.assemble(request, response, base / ('bad-' + mutation))
                (response / 'record.sig').write_bytes(signature); (response / 'response.json').write_bytes(metadata)
            report.write_bytes(b'changed external report')
            with self.assertRaises(ValueError): qualification.prepare(observer, report, fixture.inputs, profile['profile_id'], 'Certifier', base / 'wrong-report')

    def test_closed_machine_and_installation_descriptor_refuses_ambiguous_claims(self):
        valid = {'schema_version': 1, 'level': 'execution', 'installation_sha256': '12' * 32,
            'release_manifest_sha256': '34' * 32, 'model_profile_sha256': '56' * 32,
            'runtime_tuple_sha256': '78' * 32, 'test_report_sha256': 'ab' * 32,
            'hardware': {'cpu_vendor': 'GenuineIntel', 'cpu_family': 6, 'cpu_model': 123, 'cpu_stepping': 1,
                'features': ['avx', 'avx2'], 'logical_cpus': 4, 'total_memory_bytes': 16 * 1024**3}}
        qualification.evidence(qualification.production.canonical(valid))
        for case in range(7):
            changed = deepcopy(valid)
            if case == 0: del changed['installation_sha256']
            elif case == 1: changed['trusted'] = True
            elif case == 2: changed['hardware']['features'] = ['avx2', 'avx']
            elif case == 3: changed['hardware']['features'] = ['avx', 'avx']
            elif case == 4: changed['hardware']['logical_cpus'] = True
            elif case == 5: changed['hardware']['cpu_vendor'] = ' GenuineIntel'
            else: changed['level'] = 'self-certified'
            with self.subTest(case=case), self.assertRaises(ValueError): qualification.evidence(qualification.production.canonical(changed))


if __name__ == '__main__': unittest.main()
