"""Real public signature packaging and lossless native tokenizer data checks."""
import base64
from dataclasses import fields
from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import provision_model_inputs as models
import derive_model_sidecars as sidecars
from test_public_trust import Fixture as Keys
from luma_os.model_catalog_signing import CatalogReleaseRequest, CatalogApproval, CatalogSignatureStatement, CatalogSignatureEnvelope, canonical_approval_set_bytes


class Fixture:
    def __init__(self, base):
        self.keys = Keys(base)
        self.root = self.keys.root
        self.inputs = base / 'model-inputs'
        self.inputs.mkdir(mode=0o700)
        self.root_pem = self.keys.key('model-root')
        self.leaf = self.keys.key('catalog')
        self.root_raw = models.public.public_der(self.root_pem)[12:]
        self.leaf_raw = models.public.public_der(self.leaf)[12:]
        self.policy = {'schema_version': 1, 'trust_domain': 'luma-models',
            'accepted_trust_policy_versions': ['trust-v1'], 'accepted_catalog_policy_versions': ['catalog-v1'],
            'roots': [{'key_id': 'ModelRoot', 'environment': 'lab', 'trust_domain': 'luma-models',
                'public_key': base64.b64encode(self.root_raw).decode(), 'not_before': '2026-10-01T00:00:00Z',
                'not_after': '2026-11-01T00:00:00Z', 'revoked_at': None}], 'separated_key_sha256': []}
        self.bundle = {'artifact_type': 'luma-os-signing-trust-bundle', 'bundle_sequence': 1,
            'environment': 'lab', 'issued_at': '2026-10-10T00:00:00Z', 'not_before': '2026-10-02T00:00:00Z',
            'not_after': '2026-10-31T00:00:00Z', 'policy_version': 'trust-v1', 'previous_bundle_sha256': None,
            'root_key_id': 'ModelRoot', 'schema_version': 1, 'trust_domain': 'luma-models',
            'keys': [{'environment': 'lab', 'key_id': 'Catalog', 'not_after': '2026-10-30T00:00:00Z',
                'not_before': '2026-10-03T00:00:00Z', 'public_key': base64.b64encode(self.leaf_raw).decode(),
                'public_key_encoding': 'raw-ed25519-base64', 'purposes': ['model-profile-catalog-lab'],
                'revocation_reason': None, 'revoked_at': None, 'role': 'model-profile-catalog-lab-signer'}]}
        self.catalog = {'schema_version': 1, 'catalog_id': 'FixtureModels', 'profiles': [
            {'kind': 'manual-only', 'profile_id': 'manual-only', 'remote_fallback': False}]}
        self.refresh()

    def put(self, name, value):
        (self.inputs / name).parent.mkdir(parents=True, exist_ok=True)
        (self.inputs / name).write_bytes(value if isinstance(value, bytes) else models.canonical(value))

    def pack(self, production=False, availability='available'):
        n = json.loads(Path(sidecars.__file__).with_name('model-catalog.json').read_bytes())['models'][0]
        tuple_value = {'os_family': 'Linux', 'architecture': 'amd64', 'backend': 'llama.cpp',
                       'backend_version': 'b11100', 'device': 'cpu'}
        tuple_digest = models.public.sha(models.canonical(tuple_value))
        signer = self.keys.key('pack')
        environment = 'production' if production else 'lab'
        if production:
            self.policy['roots'][0]['environment'] = environment
            self.bundle['environment'] = environment
            self.bundle['keys'][0].update(environment=environment, purposes=['model-profile-catalog-production'],
                                        role='model-profile-catalog-production-signer')
            identity = self.root / 'usr/share/luma-os/release-identity.json'
            value = json.loads(identity.read_bytes()); value['environment'] = environment
            identity.write_bytes(models.canonical(value))
        self.bundle['keys'].append({'environment': environment, 'key_id': 'Pack',
            'not_after': '2026-10-30T00:00:00Z', 'not_before': '2026-10-03T00:00:00Z',
            'public_key': base64.b64encode(models.public.public_der(signer)[12:]).decode(),
            'public_key_encoding': 'raw-ed25519-base64', 'purposes': ['model-pack-manifest'],
            'revocation_reason': None, 'revoked_at': None, 'role': 'model-pack-signer'})
        blobs = [{'role': 'model', 'path': 'blobs/sha256/' + n['sha256'], 'sha256': n['sha256'],
                  'size_bytes': n['bytes'], 'shard_index': 0}]
        auxiliary = {}
        for role, data in [('tokenizer', b'{"format":"fixture-public-metadata"}'),
                           ('template', b'{{ messages }}'), ('license', b'Apache-2.0 external fixture')]:
            digest = models.public.sha(data)
            name = ('licenses/' + digest + '.txt') if role == 'license' else ('blobs/sha256/' + digest)
            blobs.append({'role': role, 'path': name, 'sha256': digest, 'size_bytes': len(data)})
            auxiliary[name] = data
        manifest = {'schema_version': 2, 'canonicalization': 'RFC8785-ASCII-v1',
            'signature_algorithm': 'Ed25519', 'pack_id': n['id'], 'pack_version': '1.0.0',
            'model': {'architecture': 'qwen3', 'identity': 'Qwen/Qwen3-4B-GGUF', 'parameter_class': '4B',
                'total_parameters': n['parameters'], 'active_parameters_min': n['active_parameters'],
                'active_parameters_max': n['active_parameters'], 'quantization': 'Q4_K_M',
                'required_features': ['chat-completion', 'text-generation'], 'source': n['url']},
            'context': {'maximum_tokens': n['context_tokens'], 'template_sha256': blobs[2]['sha256']},
            'blobs': blobs, 'runtime_tuples': [tuple_value], 'installation_profiles': [{
                'profile_id': n['id'], 'runtime_tuple_sha256': tuple_digest, 'execution_mode': 'cpu',
                'minimum_host_ram_bytes': n['minimum_ram_bytes'], 'minimum_accelerator_memory_bytes': 0,
                'minimum_model_storage_bytes': sum(b['size_bytes'] for b in blobs) + n['bytes'] + models.RESERVE,
                'maximum_context_tokens': n['context_tokens']}],
            'license': {'identifier': n['license'], 'evaluation': 'approved', 'redistribution': 'approved',
                        'files': [blobs[3]['path']]}, 'network_default': 'deny', 'signer_key_id': 'Pack'}
        parsed = models.ModelManifest.parse(models.canonical(manifest))
        digest = models.public.sha(parsed.canonical_bytes)
        prefix = 'model-packs/' + digest + '/'
        self.put(prefix + 'manifest.json', parsed.canonical_bytes)
        self.put(prefix + 'manifest.sig', bytes.fromhex(self.keys.sign('pack', parsed.canonical_bytes)))
        for name, data in auxiliary.items(): self.put(prefix + name, data)
        p = {'availability': availability, 'certification_state': 'interactive-certified' if production else 'not-certified',
            'context_tokens': n['context_tokens'], 'development_state': 'development-tested', 'execution_mode': 'cpu',
            'install_bytes': sum(b['size_bytes'] for b in blobs), 'kind': 'model',
            'load_reservations': [{'domain': 'host', 'bytes': n['memory_max_bytes']}],
            'minimum_accelerator_memory_bytes': 0, 'minimum_host_ram_bytes': n['minimum_ram_bytes'],
            'model_pack_manifest_sha256': digest, 'parameter_active_max': n['active_parameters'],
            'parameter_active_min': n['active_parameters'], 'parameter_total': n['parameters'],
            'profile_id': n['id'], 'remote_fallback': False, 'runtime_tuple_sha256': tuple_digest,
            'serve_reservations': [{'domain': 'host', 'bytes': n['memory_max_bytes']}],
            'storage_peak_bytes': manifest['installation_profiles'][0]['minimum_model_storage_bytes'],
            'verification_state': 'verified'}
        self.catalog['profiles'].append(p)
        self.refresh()
        if production: (self.inputs / 'catalog-envelope.json').unlink()
        return prefix, p

    def refresh(self):
        self.put('model-roots.json', self.policy)
        signature = bytes.fromhex(self.keys.sign('model-root', models.canonical(self.bundle)))
        self.put('model-trust.json', {'bundle': self.bundle, 'schema_version': 1,
            'signature': base64.b64encode(signature).decode(), 'signature_algorithm': 'Ed25519', 'signature_encoding': 'base64'})
        self.put('catalog.json', self.catalog)
        start = datetime(2026, 10, 4, tzinfo=timezone.utc)
        end = datetime(2026, 10, 20, tzinfo=timezone.utc)
        signed = datetime(2026, 10, 12, tzinfo=timezone.utc)
        request = CatalogReleaseRequest(environment='lab', release_id='FixtureImage', catalog_id='FixtureModels',
            catalog_sha256=models.public.sha(models.canonical(self.catalog)), catalog_sequence=1,
            policy_version='catalog-v1', signer_key_id='Catalog', signing_principal_id='Custodian',
            signing_activity='model-catalog.sign.lab', signing_assignment_id='SignAssignment',
            signing_assignment_receipt_sha256='a' * 64, not_before=start, not_after=end)
        approval = CatalogApproval(activity='model-catalog.approve.lab-release', principal_id='Approver',
            assignment_id='ReleaseAssignment', assignment_receipt_sha256='b' * 64,
            approval_decision_receipt_sha256='c' * 64, release_request_sha256=request.digest,
            release_id='FixtureImage', catalog_sha256=request.catalog_sha256, approved_at=signed)
        statement = CatalogSignatureStatement(**{k: v for k, v in {
            **request.canonical_payload(), 'artifact_type': 'model-profile-catalog',
            'release_request_sha256': request.digest,
            'approval_set_sha256': models.public.sha(canonical_approval_set_bytes((approval,))),
            'signed_at': signed, 'not_before': start, 'not_after': end}.items() if k in {field.name for field in fields(CatalogSignatureStatement)}})
        signature = bytes.fromhex(self.keys.sign('catalog', statement.canonical_bytes))
        self.put('catalog-envelope.json', CatalogSignatureEnvelope(statement, (approval,), signature).canonical_bytes)


class ModelInputsTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def test_absence_does_not_generate_keys_or_authority(self):
        self.assertEqual(models.provision(Path('/nonexistent'), None),
                         {'schema_version': 1, 'provided': False, 'activated': False})

    def test_real_root_leaf_and_catalog_signatures_package_only_inert_public_data(self):
        f = self.fixture()
        result = models.provision(f.root, f.inputs)
        self.assertTrue(result['provided'])
        self.assertFalse(result['activated'])
        self.assertEqual((f.root / 'usr/share/luma-os/models/catalog.json').read_bytes(), models.canonical(f.catalog))
        self.assertFalse((f.root / 'var/lib/luma-os/admin').exists())

    def test_target_catalog_envelope_can_be_created_after_factory_packaging(self):
        f = self.fixture()
        (f.inputs / 'catalog-envelope.json').unlink()
        result = models.provision(f.root, f.inputs)
        self.assertTrue(result['provided'])
        self.assertFalse(result['activated'])
        self.assertFalse((f.root / 'usr/share/luma-os/models/catalog-envelope.json').exists())

    def test_unknown_private_file_and_partial_groups_refuse_before_publication(self):
        f = self.fixture()
        f.put('model-root.key', b'private fixture')
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)
        (f.inputs / 'model-root.key').unlink()
        (f.inputs / 'model-roots.json').unlink()
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)
        self.assertFalse((f.root / 'usr/share/luma-os/model-roots.json').exists())

    def test_tampered_signature_duplicate_json_and_environment_refuse(self):
        f = self.fixture()
        value = json.loads((f.inputs / 'model-trust.json').read_bytes())
        value['signature'] = base64.b64encode(bytes(64)).decode()
        f.put('model-trust.json', value)
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)
        f.refresh()
        raw = (f.inputs / 'model-roots.json').read_bytes()
        f.put('model-roots.json', raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)
        f.refresh()
        image = f.root / 'usr/share/luma-os/release-identity.json'
        value = json.loads(image.read_bytes()); value['environment'] = 'production'; image.write_bytes(models.canonical(value))
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)

    def test_actual_packaged_os_key_reuse_refuses_even_empty_separation_list(self):
        f = self.fixture()
        f.policy['roots'][0]['public_key'] = base64.b64encode(models.public.public_der(f.keys.release)[12:]).decode()
        f.put('model-roots.json', f.policy)
        with self.assertRaisesRegex(ValueError, 'reuses'): models.provision(f.root, f.inputs)

    def test_symlink_and_hardlink_members_refuse(self):
        f = self.fixture()
        member = f.inputs / 'catalog.json'
        saved = member.read_bytes(); member.unlink(); member.symlink_to(f.inputs / 'model-trust.json')
        with self.assertRaises((ValueError, OSError)): models.provision(f.root, f.inputs)
        member.unlink(); member.write_bytes(saved)
        import os
        os.link(member, f.inputs / 'duplicate.json')
        with self.assertRaises(ValueError): models.provision(f.root, f.inputs)

    def test_real_signed_compiled_pack_public_metadata_does_not_embed_weights(self):
        f = self.fixture(); prefix, p = f.pack()
        result = models.provision(f.root, f.inputs)
        self.assertTrue(result['provided']); self.assertFalse(result['activated'])
        n = json.loads(Path(sidecars.__file__).with_name('model-catalog.json').read_bytes())['models'][0]
        self.assertFalse((f.root / 'usr/share/luma-os' / prefix / ('blobs/sha256/' + n['sha256'])).exists())
        self.assertEqual(p['load_reservations'][0]['domain'], 'host')

    def test_signed_compiled_pack_understated_native_memory_refuses(self):
        f = self.fixture(); _, p = f.pack()
        p['load_reservations'][0]['bytes'] = 1
        f.refresh()
        with self.assertRaisesRegex(ValueError, 'understates'): models.provision(f.root, f.inputs)

    def test_production_factory_omits_final_image_certificates_and_refuses_embedding_them(self):
        f = self.fixture(); _, p = f.pack(production=True, availability='unavailable')
        result = models.provision(f.root, f.inputs)
        self.assertTrue(result['provided']); self.assertEqual(result['environment'], 'production')
        self.assertFalse((f.root / 'usr/share/luma-os/model-certifications').exists())
        f.put('model-certifications/' + p['model_pack_manifest_sha256'] + '/execution.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'undeclared'): models.provision(f.root, f.inputs)


class SidecarTests(unittest.TestCase):
    def profile(self):
        return json.loads(Path(sidecars.__file__).with_name('model-catalog.json').read_bytes())['models'][0]

    def fields(self):
        n = self.profile()['layout']
        text = lambda value: struct.pack('<Q', len(value.encode())) + value.encode()
        result = [('general.architecture', 8, text('qwen3'))]
        for key, value in [('block_count', n['layers']), ('embedding_length', n['embedding']),
            ('attention.head_count', n['attention_heads']), ('attention.head_count_kv', n['kv_heads']),
            ('attention.key_length', n['key_width']), ('attention.value_length', n['value_width']),
            ('context_length', n['training_context'])]: result.append(('qwen3.' + key, 4, struct.pack('<I', value)))
        result.extend([('tokenizer.ggml.model', 8, text('gpt2')),
            ('tokenizer.ggml.tokens', 9, struct.pack('<IQ', 8, 2) + text('hello') + text('世界')),
            ('tokenizer.ggml.scores', 9, struct.pack('<IQff', 6, 2, -1.5, 0.125)),
            ('tokenizer.chat_template', 8, text('{{ messages }}\n'))])
        return result

    def encoded(self, fields):
        text = lambda value: struct.pack('<Q', len(value.encode())) + value.encode()
        return b'GGUF' + struct.pack('<IQQ', 3, 1, len(fields)) + b''.join(text(k) + struct.pack('<I', t) + v for k, t, v in fields)

    def test_sidecars_preserve_sorted_exact_encoded_values_float_bits_and_unicode(self):
        fields = self.fields()
        raw = self.encoded(list(reversed(fields)))
        tokenizer, template = sidecars.extract(BytesIO(raw), len(raw), self.profile())
        value = json.loads(tokenizer)
        self.assertEqual(tokenizer, sidecars.canonical(value))
        self.assertEqual(template, b'{{ messages }}\n')
        self.assertEqual([v['key'] for v in value['entries']], sorted(k for k, _, _ in fields if k.startswith('tokenizer.') and k != 'tokenizer.chat_template'))
        for entry in value['entries']:
            original = next(v for k, _, v in fields if k == entry['key'])
            self.assertEqual(bytes.fromhex(entry['value_hex']), original)

    def test_missing_duplicate_nested_invalid_boolean_and_shape_refuse(self):
        fields = self.fields()
        changes = [fields[:-1], fields + [fields[-1]],
                   fields + [('tokenizer.extra', 9, struct.pack('<IQ', 9, 1))],
                   fields + [('tokenizer.flag', 7, b'\x02')],
                   [('general.architecture', 8, struct.pack('<Q', 5) + b'llama')] + fields[1:]]
        for candidate in changes:
            raw = self.encoded(candidate)
            with self.assertRaises(ValueError): sidecars.extract(BytesIO(raw), len(raw), self.profile())

    def test_truncation_and_metadata_bounds_refuse(self):
        raw = self.encoded(self.fields())
        for candidate in (raw[:23], raw[:-1], b'GGUF' + struct.pack('<IQQ', 3, 1, 4097)):
            with self.assertRaises(ValueError): sidecars.extract(BytesIO(candidate), len(candidate), self.profile())


if __name__ == '__main__': unittest.main()
