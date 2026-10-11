"""Actual public Ed25519 packaging checks; private keys are disposable fixtures."""
from pathlib import Path
import subprocess
import base64
import os
import tempfile
import unittest
from unittest.mock import patch

import provision_public_trust as public


class Fixture:
    def __init__(self, base, environment='lab'):
        self.base = base
        self.root = base / 'root'
        self.inputs = base / 'inputs'
        self.keys = base / 'disposable-test-keys'
        for directory in (self.root, self.inputs, self.keys):
            directory.mkdir(mode=0o700)
        share = self.root / 'usr/share/luma-os'
        share.mkdir(parents=True, mode=0o755)
        self.release = self.key('release')
        (share / 'release.pub').write_bytes(self.release)
        (share / 'release-identity.json').write_bytes(public.compact({
            'schema_version': 1, 'release': 'FixtureImage', 'sequence': 1,
            'environment': environment, 'architecture': 'amd64', 'ubuntu': '24.04', 'edition': 'headless'}))
        self.root_key = self.key('skill-root')
        self.leaf = self.key('skill-leaf')
        self.production = self.key('production-release')
        self.root_name, self.policy_name = public.ROOTS[environment]
        self.put(self.root_name, self.root_key)
        self.policy = {'schema_version': 1, 'environment': environment, 'domain': 'skill-registry',
                       'purpose': 'skill-registry', 'root_sha256': public.sha(public.public_der(self.root_key)),
                       'not_before_ms': 1000, 'expires_ms': 1000000, 'separated_key_sha256': []}
        self.trust = {'schema_version': 1, 'environment': environment, 'domain': 'skill-registry',
                      'purpose': 'skill-registry', 'policy': 'closed-file-to-artifact-v1', 'version': 1,
                      'previous_sha256': '0' * 64, 'root_sha256': self.policy['root_sha256'],
                      'not_before_ms': 2000, 'expires_ms': 900000,
                      'keys': [{'id': 'RegistrySigner', 'public_key_hex': public.public_der(self.leaf)[12:].hex(),
                                'role': 'skill-registry-signer', 'purpose': 'skill-registry',
                                'not_before_ms': 3000, 'expires_ms': 800000, 'revoked': False}]}
        self.graph = (Path(__file__).parent / 'overlay/usr/share/luma-os/workflows/file-to-artifact-v1.json').read_bytes()
        self.registry = {'schema_version': 2, 'environment': environment, 'profile': 'file-to-artifact-v1',
                         'workflow_sha256': public.sha(self.graph), 'skills': [
                             {'id': 'file-read', 'input_types': [], 'output_type': 'text'},
                             {'id': 'deterministic-calculate', 'input_types': ['text'], 'output_type': 'report'},
                             {'id': 'artifact-write', 'input_types': ['report'], 'output_type': 'artifact'}]}
        self.counter = 0
        self.refresh()

    def key(self, name):
        private = self.keys / (name + '.key')
        subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(private)],
                       check=True, capture_output=True, timeout=5)
        private.chmod(0o600)
        return subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout'],
                              check=True, capture_output=True, timeout=5).stdout

    def sign(self, name, message):
        self.counter += 1
        path = self.keys / ('message-' + str(self.counter))
        path.write_bytes(message)
        return subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
                               str(self.keys / (name + '.key')), '-in', str(path)],
                              check=True, capture_output=True, timeout=5).stdout.hex()

    def put(self, name, value):
        (self.inputs / name).write_bytes(value if isinstance(value, bytes) else public.compact(value))

    def refresh(self):
        self.put(self.policy_name, self.policy)
        signed = {'trust': self.trust, 'signature_hex': self.sign('skill-root', public.compact(self.trust))}
        self.put('skill-trust.json', signed)
        self.put('file-to-artifact-v1.json', self.graph)
        self.put('registry.json', self.registry)
        self.metadata = {'schema_version': 1, 'environment': self.trust['environment'], 'domain': 'skill-registry',
                         'purpose': 'skill-registry', 'policy': 'closed-file-to-artifact-v1', 'sequence': 1,
                         'trust_version': self.trust['version'], 'trust_sha256': public.sha(public.compact(signed)),
                         'registry_sha256': public.sha((self.inputs / 'registry.json').read_bytes()),
                         'workflow_sha256': public.sha(self.graph), 'not_before_ms': 4000,
                         'expires_ms': 700000, 'signer': 'RegistrySigner'}
        self.put('skill-admission.json', {'metadata': self.metadata,
                                        'signature_hex': self.sign('skill-leaf', public.compact(self.metadata))})


class PublicTrustTests(unittest.TestCase):
    def test_only_one_nonzero_ed25519_public_spki_can_be_a_packaged_root(self):
        pem = lambda data: (b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(data) +
                            b'\n-----END PUBLIC KEY-----\n')
        self.assertEqual(public.public_der(pem(public.SPKI + b'\x01' * 32)), public.SPKI + b'\x01' * 32)
        for invalid in (pem(public.SPKI + bytes(32)), pem(b'RSA' + b'\x01' * 41),
                        b'-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n',
                        pem(public.SPKI + b'\x01' * 32) * 2):
            with self.assertRaises(ValueError):
                public.public_der(invalid)

    def test_absence_preserves_baseline_without_keys_or_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(public.provision(root), {'schema_version': 1, 'provided': False,
                                                      'skill_registry': False, 'activated': False})
            self.assertEqual(list(root.iterdir()), [])

    def test_real_signed_lab_and_production_inputs_publish_exact_public_only_bytes(self):
        for environment in ('lab', 'production'):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary), environment)
                f.put('production-release-root.pub', f.production)
                result = public.provision(f.root, f.inputs)
                self.assertFalse(result['activated'])
                self.assertTrue(result['skill_registry'])
                self.assertEqual(result['environment'], environment)
                for relative, digest in result['files'].items():
                    target = f.root / relative
                    self.assertEqual(public.sha(target.read_bytes()), digest)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                self.assertEqual((f.root / 'usr/share/luma-os/skills/registry.json').read_bytes(),
                                 (f.inputs / 'registry.json').read_bytes())
                self.assertFalse((f.root / 'var/lib/luma-os/admin').exists())
                self.assertFalse(list(f.root.rglob('*.key')))

    def test_production_release_public_root_is_an_independent_complete_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = Fixture(Path(temporary))
            for member in f.inputs.iterdir():
                member.unlink()
            f.put('production-release-root.pub', f.production)
            result = public.provision(f.root, f.inputs)
            self.assertFalse(result['skill_registry'])
            self.assertEqual(len(result['files']), 1)
            self.assertFalse((f.root / 'usr/share/luma-os/skills/registry.json').exists())

    def test_partial_mixed_unknown_and_private_inputs_never_publish(self):
        for change in ('missing', 'opposite-root', 'private', 'unknown'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                if change == 'missing':
                    (f.inputs / 'skill-admission.json').unlink()
                elif change == 'opposite-root':
                    f.put('production-skill-root.pub', f.production)
                else:
                    f.put('private.key' if change == 'private' else 'unexpected.json', b'refuse')
                with self.assertRaises(ValueError):
                    public.provision(f.root, f.inputs)
                self.assertFalse((f.root / 'usr/share/luma-os/skills').exists())

    def test_wrong_root_or_leaf_signatures_refuse_before_publication(self):
        for filename in ('skill-trust.json', 'skill-admission.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                signed = public.document((f.inputs / filename).read_bytes())
                signed['signature_hex'] = '0' * 128
                f.put(filename, signed)
                with self.assertRaisesRegex(ValueError, 'signature refuses'):
                    public.provision(f.root, f.inputs)
                self.assertFalse((f.root / 'usr/share/luma-os/skills').exists())

    def test_runtime_known_release_key_reuse_refuses_even_empty_historical_policy(self):
        for key_type in ('root', 'leaf', 'production-release'):
            with self.subTest(key_type=key_type), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                if key_type == 'root':
                    f.put(f.root_name, f.release)
                    f.policy['root_sha256'] = public.sha(public.public_der(f.release))
                    f.trust['root_sha256'] = f.policy['root_sha256']
                    f.refresh()
                elif key_type == 'leaf':
                    f.trust['keys'][0]['public_key_hex'] = public.public_der(f.release)[12:].hex()
                    f.refresh()
                else:
                    f.put('production-release-root.pub', f.release)
                with self.assertRaises(ValueError):
                    public.provision(f.root, f.inputs)

    def test_policy_domain_validity_duplicate_separation_and_unknown_fields_refuse(self):
        for change in ('domain', 'validity', 'duplicate', 'extra', 'boolean-schema'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                if change == 'domain':
                    f.policy['purpose'] = 'os-release'
                elif change == 'validity':
                    f.policy['expires_ms'] = f.policy['not_before_ms']
                elif change == 'duplicate':
                    f.policy['separated_key_sha256'] = ['ab' * 32, 'ab' * 32]
                elif change == 'extra':
                    f.policy['authority'] = True
                else:
                    f.policy['schema_version'] = True
                f.put(f.policy_name, f.policy)
                with self.assertRaises(ValueError):
                    public.provision(f.root, f.inputs)

    def test_registry_cannot_change_the_image_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = Fixture(Path(temporary), 'production')
            identity = f.root / 'usr/share/luma-os/release-identity.json'
            value = public.document(identity.read_bytes())
            value['environment'] = 'lab'
            identity.write_bytes(public.compact(value))
            with self.assertRaisesRegex(ValueError, 'image identity'):
                public.provision(f.root, f.inputs)
            self.assertFalse((f.root / 'usr/share/luma-os/skills').exists())

    def test_signed_wrong_registry_types_or_disconnected_graph_still_refuse(self):
        for change in ('schema', 'skills', 'cycle', 'unused'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                if change == 'schema':
                    f.registry['schema_version'] = 1
                elif change == 'skills':
                    f.registry['skills'][0]['extra'] = 'script'
                else:
                    graph = public.document(f.graph)
                    if change == 'cycle':
                        graph['nodes'][0]['dependencies'] = ['publish']
                        graph['nodes'][0]['input_types'] = ['artifact']
                    else:
                        graph['nodes'].append({'id': 'unused', 'kind': 'file-read', 'dependencies': [],
                                               'input_types': [], 'output_type': 'text'})
                    f.graph = public.compact(graph)
                    f.registry['workflow_sha256'] = public.sha(f.graph)
                f.refresh()
                with self.assertRaises(ValueError):
                    public.provision(f.root, f.inputs)

    def test_duplicate_json_revoked_leaf_and_oversized_input_refuse(self):
        for change in ('duplicate', 'revoked', 'oversize'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                if change == 'duplicate':
                    data = (f.inputs / f.policy_name).read_bytes()
                    f.put(f.policy_name, b'{"schema_version":1,' + data[1:])
                elif change == 'revoked':
                    f.trust['keys'][0]['revoked'] = True
                    f.refresh()
                else:
                    f.put('registry.json', b'x' * 4097)
                with self.assertRaises(ValueError):
                    public.provision(f.root, f.inputs)

    def test_no_follow_and_post_crypto_source_substitution_are_not_adopted(self):
        for change in ('link', 'hardlink', 'after-crypto'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                f = Fixture(Path(temporary))
                path = f.inputs / 'registry.json'
                if change == 'link':
                    saved = f.base / 'saved-registry'
                    saved.write_bytes(path.read_bytes())
                    path.unlink(); path.symlink_to(saved)
                    with self.assertRaises(OSError):
                        public.provision(f.root, f.inputs)
                elif change == 'hardlink':
                    os.link(path, f.base / 'extra-link')
                    with self.assertRaises(ValueError):
                        public.provision(f.root, f.inputs)
                else:
                    original = public.verify
                    def replace(*arguments):
                        original(*arguments)
                        path.write_bytes(path.read_bytes() + b' ')
                    with patch.object(public, 'verify', side_effect=replace), self.assertRaises(ValueError):
                        public.provision(f.root, f.inputs)
                self.assertFalse((f.root / 'usr/share/luma-os/skills').exists())

    def test_image_symlink_parent_never_receives_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            f = Fixture(base)
            outside = base / 'outside'
            outside.mkdir()
            (f.root / 'usr/share/luma-os/skills').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                public.provision(f.root, f.inputs)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
