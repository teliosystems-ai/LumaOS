#!/usr/bin/env python3
"""Prepare/verify genuine external model-certification inputs, never certify QA.

The actual installed importer independently checks current TPM, installation,
acknowledged image, hardware, custody, protected UTC and finite Admin authority.
This utility only binds a supplied report and public signature to exact bytes.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys

import production_release as production
import provision_public_trust as public
import provision_model_inputs as model
from luma_os.model_pack import ModelManifest, CertificationRecord
from luma_os.signing_trust import SignedTrustBundle, RootTrustAnchor

EVIDENCE_FIELDS = ('schema_version', 'level', 'installation_sha256', 'release_manifest_sha256',
                  'model_profile_sha256', 'runtime_tuple_sha256', 'hardware', 'test_report_sha256')
HARDWARE_FIELDS = ('cpu_vendor', 'cpu_family', 'cpu_model', 'cpu_stepping', 'features',
                   'logical_cpus', 'total_memory_bytes')


def evidence(data):
    value = production.exact(data, EVIDENCE_FIELDS)
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['level'] not in ('execution', 'interactive'):
        raise ValueError('unsupported exact native qualification evidence')
    for field in EVIDENCE_FIELDS[2:6] + ('test_report_sha256',):
        public.hexadecimal(value[field], 32)
    machine = public.closed(value['hardware'], HARDWARE_FIELDS)
    if type(machine['cpu_vendor']) is not str or not 1 <= len(machine['cpu_vendor']) <= 32 or not machine['cpu_vendor'].isascii() or machine['cpu_vendor'].strip() != machine['cpu_vendor'] or any(ord(c) < 32 for c in machine['cpu_vendor']):
        raise ValueError('invalid measured CPU vendor')
    for field in ('cpu_family', 'cpu_model', 'cpu_stepping'):
        public.integer(machine[field], 1 if field == 'cpu_family' else 0, 65535)
    public.integer(machine['logical_cpus'], 1, 65536)
    public.integer(machine['total_memory_bytes'], 1, 2**53 - 1)
    features = machine['features']
    if type(features) is not list or not 1 <= len(features) <= 512 or features != sorted(set(features)):
        raise ValueError('qualification CPU features must be finite, unique and sorted')
    import re
    if any(type(feature) is not str or not re.fullmatch('[a-z0-9_]{1,64}', feature) for feature in features):
        raise ValueError('invalid measured CPU feature')
    return value


def authority(values, signer, level):
    policy = model.closed(model.document(values['model-roots.json']),
        ('schema_version', 'trust_domain', 'accepted_trust_policy_versions',
         'accepted_catalog_policy_versions', 'roots', 'separated_key_sha256'))
    if type(policy['schema_version']) is not int or policy['schema_version'] != 1 or policy['trust_domain'] != 'luma-models':
        raise ValueError('wrong independently provisioned model root policy')
    for field in ('accepted_trust_policy_versions', 'accepted_catalog_policy_versions'):
        model.strings(policy[field], 32)
    separated = policy['separated_key_sha256']
    if type(separated) is not list or len(separated) > 1024 or separated != sorted(set(separated)):
        raise ValueError('invalid model key-separation policy')
    for fingerprint in separated: public.hexadecimal(fingerprint, 32)
    if type(policy['roots']) is not list or not 1 <= len(policy['roots']) <= 32:
        raise ValueError('model roots must be a bounded public inventory')
    roots = {}; keys = set()
    for raw in policy['roots']:
        model.closed(raw, ('key_id', 'environment', 'trust_domain', 'public_key', 'not_before', 'not_after', 'revoked_at'))
        key = model.raw_key(raw['public_key'])
        anchor = RootTrustAnchor(raw['key_id'], raw['environment'], raw['trust_domain'], key,
            model.timestamp(raw['not_before']), model.timestamp(raw['not_after']),
            model.timestamp(raw['revoked_at']) if raw['revoked_at'] is not None else None)
        if anchor.trust_domain != 'luma-models' or anchor.key_id in roots or key in keys or public.sha(public.SPKI + key) in separated:
            raise ValueError('model root identity/separation differs')
        roots[anchor.key_id] = anchor; keys.add(key)
    trust = SignedTrustBundle.parse(values['model-trust.json'])
    anchor = roots.get(trust.root_key_id)
    if anchor is None or trust.environment != 'production' or anchor.environment != 'production' or trust.trust_domain != 'luma-models' or trust.policy_version not in policy['accepted_trust_policy_versions'] or trust.not_before < anchor.not_before or trust.not_after > anchor.not_after or anchor.revoked_at is not None and trust.not_after > anchor.revoked_at:
        raise ValueError('qualification trust escapes approved production root/policy')
    public.verify(public.SPKI + anchor.public_key, model.canonical(model.document(values['model-trust.json'])['bundle']), trust.signature)
    all_keys = {key.key_id: key for key in trust.keys}
    for key in all_keys.values():
        if key.public_key in keys or public.sha(public.SPKI + key.public_key) in separated:
            raise ValueError('model signer reuses another public trust domain')
    selected = all_keys.get(signer)
    purpose = 'model-pack-' + level + '-certification'
    # Frozen certification records have no signing-time field. Neither the
    # bundle's issue time nor the workstation clock is current authorization;
    # the installed importer checks the entire live protected UTC interval.
    if selected is None or purpose not in {p.value for p in selected.purposes} or selected.environment != 'production' or selected.revoked_at is not None:
        raise ValueError('certifier is unknown, wrong-purpose/environment or revoked')
    return public.SPKI + selected.public_key, all_keys


def prepare(observer, report, public_inputs, profile_id, signer, out, previous=None):
    observed = public.closed(public.document(production.release.read(Path(observer), 65536)),
                             ('schema_version', 'evidence', 'evidence_sha256', 'certified', 'authority_returned'))
    descriptor = evidence(production.canonical(observed['evidence']))
    if observed['schema_version'] != 1 or observed['certified'] is not False or observed['authority_returned'] is not False or observed['evidence_sha256'] != public.sha(production.canonical(descriptor)):
        raise ValueError('native unsigned observation has altered evidence or authority claims')
    if previous is not None: public.hexadecimal(previous, 32)
    with public.Directory(Path(report).parent) as directory:
        actual = production.artifact_hash(directory, Path(report).name, 256 * 1024**2)
        directory.recheck()
    if actual['sha256'] != descriptor['test_report_sha256']:
        raise ValueError('genuine external QA report differs from measured descriptor')
    with ExitStack() as stack:
        tree = model.Tree(public_inputs, stack)
        values = tree.values
        cert_key, keys = authority(values, signer, descriptor['level'])
        catalog = model.parse_canonical_catalog(values['catalog.json'])
        candidates = [p for p in catalog.profiles if p.kind != 'manual-only' and p.profile_id == profile_id]
        if len(candidates) != 1:
            raise ValueError('qualification requires one exact public model profile')
        profile = candidates[0].canonical_payload()
        if public.sha(model.canonical(profile)) != descriptor['model_profile_sha256'] or profile['runtime_tuple_sha256'] != descriptor['runtime_tuple_sha256']:
            raise ValueError('qualification observer differs from the actual signed model profile')
        prefix = 'model-packs/' + profile['model_pack_manifest_sha256'] + '/'
        manifest = ModelManifest.parse(values[prefix + 'manifest.json'])
        pack_key = keys.get(manifest.signer_key_id)
        if pack_key is None or 'model-pack-manifest' not in {p.value for p in pack_key.purposes} or pack_key.revoked_at is not None:
            raise ValueError('model pack signer is unavailable')
        if public.sha(manifest.canonical_bytes) != profile['model_pack_manifest_sha256']:
            raise ValueError('qualification model manifest digest differs')
        public.verify(public.SPKI + pack_key.public_key, manifest.canonical_bytes, values[prefix + 'manifest.sig'])
        record = CertificationRecord(descriptor['level'], profile['model_pack_manifest_sha256'],
            descriptor['runtime_tuple_sha256'], public.sha(production.canonical(descriptor)), signer)
        request = {'schema_version': 1, 'purpose': 'model-pack-' + descriptor['level'] + '-certification',
                   'profile_id': profile_id, 'expected_previous_sha256': previous,
                   'report_sha256': actual['sha256'], 'report_bytes': actual['bytes'],
                   'signer_public_sha256': public.sha(cert_key),
                   'files': {'record.json': public.sha(record.canonical_bytes),
                             'evidence.json': public.sha(production.canonical(descriptor)),
                             'model-roots.json': public.sha(values['model-roots.json']),
                             'model-trust.json': public.sha(values['model-trust.json'])}}
        production.new_group(out, {'request.json': production.canonical(request), 'record.json': record.canonical_bytes,
            'evidence.json': production.canonical(descriptor), 'model-roots.json': values['model-roots.json'],
            'model-trust.json': values['model-trust.json']})
        tree.recheck()
    return {'request_sha256': public.sha(production.canonical(request)), 'certified': False, 'authority_returned': False}


def assemble(request_dir, response_dir, output):
    with public.Directory(request_dir) as request, public.Directory(response_dir) as response:
        if response.names != {'response.json', 'record.sig'}:
            raise ValueError('qualification response includes unknown/private inputs')
        raw = request.read('request.json', 65536)
        metadata = production.exact(raw, ('schema_version', 'purpose', 'profile_id', 'expected_previous_sha256',
            'report_sha256', 'report_bytes', 'signer_public_sha256', 'files'))
        if type(metadata['profile_id']) is not str or not 1 <= len(metadata['profile_id']) <= 512 or not metadata['profile_id'].isascii() or metadata['profile_id'].strip() != metadata['profile_id'] or any(ord(c) < 32 for c in metadata['profile_id']):
            raise ValueError('qualification request has an invalid profile selector')
        if request.names != {'request.json', 'record.json', 'evidence.json', 'model-roots.json', 'model-trust.json'} or set(metadata['files']) != request.names - {'request.json'}:
            raise ValueError('qualification request inventory changed')
        values = {name: request.read(name, 1024 * 1024) for name in metadata['files']}
        if any(public.sha(value) != metadata['files'][name] for name, value in values.items()):
            raise ValueError('qualification request byte pins differ')
        reply = production.exact(response.read('response.json', 4096), ('schema_version', 'request_sha256'))
        if reply['schema_version'] != 1 or type(reply['schema_version']) is not int or reply['request_sha256'] != public.sha(raw):
            raise ValueError('qualification signature binds a different request')
        descriptor = evidence(values['evidence.json'])
        if type(metadata['schema_version']) is not int or metadata['schema_version'] != 1 or metadata['report_sha256'] != descriptor['test_report_sha256']:
            raise ValueError('qualification request report/schema differs')
        public.integer(metadata['report_bytes'], 1, 256 * 1024**2)
        if metadata['expected_previous_sha256'] is not None:
            public.hexadecimal(metadata['expected_previous_sha256'], 32)
        record = CertificationRecord(**model.closed(model.document(values['record.json']),
            ('level', 'pack_manifest_sha256', 'runtime_tuple_sha256', 'evidence_sha256', 'signer_key_id')))
        key, _ = authority(values, record.signer_key_id, record.level)
        if public.sha(key) != metadata['signer_public_sha256'] or record.evidence_sha256 != public.sha(values['evidence.json']) or record.level != descriptor['level'] or record.runtime_tuple_sha256 != descriptor['runtime_tuple_sha256'] or metadata['purpose'] != 'model-pack-' + record.level + '-certification':
            raise ValueError('external certification record changed its exact evidence/purpose')
        signature = response.read('record.sig', 64)
        public.verify(key, record.canonical_bytes, signature)
        package = {'record': model.document(values['record.json']), 'signature_hex': signature.hex(), 'evidence': descriptor}
        result = {'package': package, 'expected_previous_sha256': metadata['expected_previous_sha256']}
        request.recheck(); response.recheck()
        production.release.exclusive_write(Path(output), production.canonical(result))
    return {'package_sha256': public.sha(production.canonical(package)),
            'external_public_signature_verified': True, 'qa_verified': False,
            'installation_authorized': False, 'authority_returned': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    p = commands.add_parser('prepare')
    for name in ('observer', 'report', 'public-inputs', 'out'): p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--profile', required=True); p.add_argument('--signer', required=True); p.add_argument('--previous-sha256')
    p = commands.add_parser('assemble')
    for name in ('request', 'response', 'output'): p.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.operation == 'prepare': result = prepare(args.observer, args.report, args.public_inputs, args.profile, args.signer, args.out, args.previous_sha256)
    else: result = assemble(args.request, args.response, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
