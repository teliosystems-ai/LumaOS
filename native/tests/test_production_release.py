"""Public ceremony software: real disposable signatures, never production QA."""
import base64
from copy import deepcopy
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import production_release as production


def run(*args):
    return subprocess.run([str(arg) for arg in args], check=True, capture_output=True,
                          timeout=120, env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}).stdout


def minimal_pe():
    data = bytearray(1024); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 132, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = 152
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<II', data, optional + 16, 4096, 4096)
    struct.pack_into('<Q', data, optional + 24, 0x400000)
    struct.pack_into('<II', data, optional + 32, 4096, 512)
    struct.pack_into('<II', data, optional + 56, 8192, 512)
    struct.pack_into('<H', data, optional + 68, 10)
    struct.pack_into('<I', data, optional + 108, 16)
    data[392:400] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, 400, 512, 4096, 512, 512)
    struct.pack_into('<I', data, 428, 0x60000020); data[512] = 0xc3
    return bytes(data)


class Fixture:
    def __init__(self, base):
        self.base = base; self.inputs = base / 'public'; self.keys = base / 'disposable-private'
        self.root = base / 'root'; self.out = base / 'out'
        for path in (self.inputs, self.keys, self.root, self.out): path.mkdir(mode=0o700)
        share = self.root / 'usr/share/luma-os'; share.mkdir(parents=True)
        self.identity = {'schema_version': 1, 'release': 'DisposableImage', 'sequence': 1,
            'environment': 'production', 'architecture': 'amd64', 'ubuntu': '24.04', 'edition': 'headless'}
        (share / 'release-identity.json').write_bytes(production.canonical(self.identity))
        for name in ('root', 'leaf'):
            run('/usr/bin/openssl', 'genpkey', '-algorithm', 'ED25519', '-out', self.keys / (name + '.key'))
            run('/usr/bin/openssl', 'pkey', '-in', self.keys / (name + '.key'), '-pubout', '-out', self.keys / (name + '.pub'))
        for name in ('pcr', 'secureboot'):
            run('/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', self.keys / (name + '.key'))
            run('/usr/bin/openssl', 'pkey', '-in', self.keys / (name + '.key'), '-pubout', '-out', self.keys / (name + '.pub'))
        run('/usr/bin/openssl', 'req', '-new', '-x509', '-sha256', '-key', self.keys / 'secureboot.key', '-subj', '/CN=DisposableTestOnly', '-days', '1', '-out', self.keys / 'secureboot.pem')
        root = (self.keys / 'root.pub').read_bytes(); leaf = (self.keys / 'leaf.pub').read_bytes()
        self.trust = {'schema_version': 1, 'environment': 'production', 'version': 1,
            'root_sha256': production.public.sha(production.public.public_der(root)), 'not_before_ms': 1000, 'expires_ms': 1000000,
            'keys': [{'id': 'ReleaseLeaf', 'public_key_hex': production.public.public_der(leaf)[12:].hex(),
                'purpose': 'os-release', 'not_before_ms': 2000, 'expires_ms': 900000, 'revoked': False}]}
        statement = self.keys / 'trust.json'; statement.write_bytes(production.canonical(self.trust))
        run('/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', self.keys / 'root.key', '-in', statement, '-out', self.keys / 'trust.sig')
        self.values = {'production-release-root.pub': root,
            'release-trust.json': production.canonical({'trust': self.trust, 'signature_hex': (self.keys / 'trust.sig').read_bytes().hex()}),
            'release-signer.json': production.canonical({'schema_version': 1, 'signer': 'ReleaseLeaf'}),
            'pcr-policy.pub': (self.keys / 'pcr.pub').read_bytes(), 'secureboot.pem': (self.keys / 'secureboot.pem').read_bytes()}
        for name, data in self.values.items(): (self.inputs / name).write_bytes(data)


class ProductionReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='luma-public-production-test-')
        cls.fixture = Fixture(Path(cls.temporary.name))

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_real_root_leaf_certificate_and_distinct_pcr_public_inputs(self):
        report = production.public_inputs(self.fixture.values)
        self.assertEqual(report['signer'], 'ReleaseLeaf')
        self.assertEqual(production.public.public_der(report['release_public']), production.public.public_der((self.fixture.keys / 'leaf.pub').read_bytes()))
        changed = deepcopy(self.fixture.values)
        for mutation in ('signature', 'root', 'lab', 'revoked', 'purpose', 'private', 'shared-rsa', 'root-leaf'):
            values = deepcopy(changed)
            bundle = production.public.document(values['release-trust.json'])
            if mutation == 'signature': bundle['signature_hex'] = '00' * 64
            elif mutation == 'root': values['production-release-root.pub'] = (self.fixture.keys / 'leaf.pub').read_bytes()
            elif mutation == 'lab': bundle['trust']['environment'] = 'lab'
            elif mutation == 'revoked': bundle['trust']['keys'][0]['revoked'] = True
            elif mutation == 'purpose': bundle['trust']['keys'][0]['purpose'] = 'skill-registry'
            elif mutation == 'private': values['pcr-policy.pub'] = (self.fixture.keys / 'pcr.key').read_bytes()
            elif mutation == 'shared-rsa': values['pcr-policy.pub'] = (self.fixture.keys / 'secureboot.pub').read_bytes()
            else: bundle['trust']['keys'][0]['public_key_hex'] = production.public.public_der(values['production-release-root.pub'])[12:].hex()
            values['release-trust.json'] = production.canonical(bundle)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): production.public_inputs(values)

    def test_public_snapshot_is_exclusive_and_no_private_member_is_accepted(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-output-test-') as path:
            base = Path(path); root = base / 'root'; out = base / 'out'
            (root / 'usr/share/luma-os').mkdir(parents=True); out.mkdir()
            result = production.validate_public_inputs(root, self.fixture.inputs, self.fixture.identity, out)
            self.assertFalse(result['activated']); self.assertFalse(result['custody_performed'])
            with self.assertRaises(FileExistsError): production.validate_public_inputs(root, self.fixture.inputs, self.fixture.identity, out)
        values = deepcopy(self.fixture.values); values['release.key'] = b'private-input-refused'
        with self.assertRaises(ValueError): production.public_inputs(values)

    def test_exact_secure_boot_signed_pe_preservation_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-pe-test-') as path:
            unsigned = Path(path) / 'unsigned.efi'; signed = Path(path) / 'signed.efi'
            original = minimal_pe(); unsigned.write_bytes(original)
            run('/usr/bin/sbsign', '--key', self.fixture.keys / 'secureboot.key', '--cert', self.fixture.keys / 'secureboot.pem', '--output', signed, unsigned)
            actual = signed.read_bytes(); production.verify_pe_preservation(original, actual)
            run('/usr/bin/sbverify', '--cert', self.fixture.keys / 'secureboot.pem', signed)
            for offset in (100, 132, 200, 512):
                changed = bytearray(actual); changed[offset] ^= 1
                with self.assertRaises(ValueError): production.verify_pe_preservation(original, bytes(changed))
            with self.assertRaises(ValueError): production.verify_pe_preservation(original, actual + b'\0' * 8)
            with self.assertRaises(ValueError): production.verify_pe_preservation(actual, actual)

    def test_streamed_artifact_bounds_namespace_and_hardlink_refusal(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-artifact-test-') as path:
            root = Path(path); file = root / 'artifact'; file.write_bytes(b'actual-image-bytes')
            with production.public.Directory(root) as directory:
                record = production.artifact_hash(directory, 'artifact', 1024)
                self.assertEqual(record['sha256'], production.public.sha(file.read_bytes()))
                with self.assertRaises(ValueError): production.artifact_hash(directory, 'artifact', 1)
            os.link(file, root / 'alias')
            with production.public.Directory(root) as directory, self.assertRaises(ValueError): production.artifact_hash(directory, 'artifact', 1024)

    def test_real_raw_manifest_signature_response_and_closed_request_boundary(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-manifest-test-') as path:
            base = Path(path); root = base / 'root'; out = base / 'out'; response = base / 'response'
            (root / 'usr/share/luma-os').mkdir(parents=True); out.mkdir(); response.mkdir()
            production.validate_public_inputs(root, self.fixture.inputs, self.fixture.identity, out)
            manifest = {**self.fixture.identity, 'root_hash': 'ab' * 32, 'root_bytes': 512 * 1024**2,
                'hash_bytes': 4096, 'artifacts': [{'name': name, 'bytes': 512 * 1024**2 if name == 'root.ext4' else 4096 if name == 'root.verity' else 1024,
                    'sha256': 'cd' * 32} for name in sorted(production.release.ARTIFACTS)]}
            raw = production.canonical(manifest)
            report = production.public_inputs(self.fixture.values)
            request = production.request_group(out, 'release', {'release.json': raw}, {'signer': 'ReleaseLeaf',
                'public_inputs': report['fingerprints'], 'signature_algorithm': 'Ed25519-raw-message'})
            run('/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', self.fixture.keys / 'leaf.key',
                '-in', out / 'production-release-request/release.json', '-out', response / 'release.sig')
            metadata = {'schema_version': 1, 'request_sha256': request['request_sha256']}
            (response / 'release-response.json').write_bytes(production.canonical(metadata))
            # This test isolates the real signature/transport boundary. Actual
            # physical artifact hashing has its separate non-mocked test above;
            # it does not claim a bootable or qualified production image.
            with patch.object(production, 'check_manifest_artifacts') as physical:
                result = production.accept_release(out, response)
                physical.assert_called_once_with(out, manifest)
                self.assertTrue(result['production_signatures_verified']); self.assertFalse(result['native_qualification'])
                for mutation in ('signature', 'request', 'unknown'):
                    signature = (response / 'release.sig').read_bytes()
                    if mutation == 'signature': (response / 'release.sig').write_bytes(bytes(64))
                    elif mutation == 'request': metadata['request_sha256'] = 'ff' * 32
                    else: metadata['trusted'] = True
                    (response / 'release-response.json').write_bytes(production.canonical(metadata))
                    with self.assertRaises(ValueError): production.accept_release(out, response)
                    (response / 'release.sig').write_bytes(signature)
                    metadata = {'schema_version': 1, 'request_sha256': request['request_sha256']}
                    (response / 'release-response.json').write_bytes(production.canonical(metadata))

    def test_external_pcr_signatures_and_signed_uki_preserve_measured_inputs(self):
        with tempfile.TemporaryDirectory(prefix='luma-production-pcr-test-') as path:
            base = Path(path); root = base / 'root'; out = base / 'out'
            share = root / 'usr/share/luma-os'; share.mkdir(parents=True); out.mkdir()
            (share / 'release-identity.json').write_bytes(production.canonical(self.fixture.identity))
            source = b'{"disposable_source":"not-a-production-build"}'
            checkpoint = {'schema_version': 1, 'identity': self.fixture.identity, 'root_hash': 'ab' * 32,
                'kernel': '6.8.0-disposable-test', 'source_lock_sha256': production.public.sha(source),
                'initrd_policy': {}, 'desktop': {'profile': 'console', 'wayland_session_tested': False}}
            (out / 'source-lock.json').write_bytes(source)
            (out / 'production-build.json').write_bytes(production.canonical(checkpoint))
            production.validate_public_inputs(root, self.fixture.inputs, self.fixture.identity, out)
            unsigned = out / 'production-unsigned'; unsigned.mkdir()
            for slot in production.SLOTS:
                image = unsigned / f'slot-{slot}.efi'; image.write_bytes(minimal_pe())
                for name, data in {'linux': b'disposable-measured-fixture-not-a-kernel', 'cmdline':
                    production.expected_cmdline(checkpoint, slot).encode(), 'uname': checkpoint['kernel'].encode(),
                    'osrel': b'ID=disposable\n'}.items():
                    member = base / f'{slot}-{name}'; member.write_bytes(data)
                    run('/usr/bin/objcopy', '--add-section', '.' + name + '=' + str(member), '--set-section-flags', '.' + name + '=contents,alloc,load,readonly,data', image)
                if slot != 'live':
                    run('/usr/bin/objcopy', '--add-section', '.pcrpkey=' + str(self.fixture.keys / 'pcr.pub'), '--set-section-flags', '.pcrpkey=contents,alloc,load,readonly,data', image)
            (unsigned / 'bootloader.efi').write_bytes(minimal_pe())
            request = production.prepare_pcr(out, root)
            response = base / 'pcr-response'; response.mkdir(); signatures = {}
            for slot in ('a', 'b'):
                signatures[slot] = []
                for index in range(2):
                    signature = base / f'{slot}-{index}.sig'
                    run('/usr/bin/openssl', 'dgst', '-sha256', '-sign', self.fixture.keys / 'pcr.key', '-out', signature, out / f'production-pcr-request/{slot}-{index}.policy')
                    signatures[slot].append(base64.b64encode(signature.read_bytes()).decode())
            (response / 'pcr-response.json').write_bytes(production.canonical({'schema_version': 1, 'request_sha256': request['request_sha256'], 'signatures': signatures}))
            pe_request = production.accept_pcr(out, response)
            signed_response = base / 'pe-response'; signed_response.mkdir(); hashes = {}
            for name in production.PE_NAMES:
                run('/usr/bin/sbsign', '--key', self.fixture.keys / 'secureboot.key', '--cert', self.fixture.keys / 'secureboot.pem', '--output', signed_response / name, out / 'production-pe-request' / name)
                hashes[name] = production.public.sha((signed_response / name).read_bytes())
            (signed_response / 'pe-response.json').write_bytes(production.canonical({'schema_version': 1, 'request_sha256': pe_request['request_sha256'], 'files': hashes}))
            result = production.accept_pe(out, signed_response)
            self.assertTrue(result['production_signatures_verified']); self.assertFalse(result['custody_verified'])
            self.assertNotIn('.pcrsig', production.boot_policy.read_sections(out / 'slot-live.efi'))
            changed = production.public.document((signed_response / 'pe-response.json').read_bytes()); changed['request_sha256'] = '00' * 32
            (signed_response / 'pe-response.json').write_bytes(production.canonical(changed))
            with self.assertRaises(ValueError): production.accept_pe(out, signed_response)

    def test_streaming_verifier_output_is_bounded_before_untrusted_process_finishes(self):
        with self.assertRaises(ValueError):
            production.command('/usr/bin/python3', '-c', 'import os; os.write(1,b"x"*5000000)')
        self.assertEqual(production.command('/usr/bin/python3', '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())', input_bytes=b'bounded-public-input'), b'bounded-public-input')
        with self.assertRaises(ValueError): production.command('/usr/bin/python3', '-c', 'pass', input_bytes=bytes(65537))


if __name__ == '__main__': unittest.main()
