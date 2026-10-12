#!/usr/bin/env python3
"""Package externally signed model data, never custody or runtime authority."""
from __future__ import annotations
import argparse
import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from luma_os.model_pack import ModelManifest, CertificationRecord
from luma_os.model_catalog_signing import parse_canonical_catalog, CatalogSignatureEnvelope
from luma_os.signing_trust import SignedTrustBundle, RootTrustAnchor

spec = importlib.util.spec_from_file_location('luma_public_inputs', Path(__file__).with_name('provision_public_trust.py'))
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
MAX_MEMBER = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
RESERVE = 2 * 1024 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def document(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    if canonical(value) != raw:
        raise ValueError('model metadata must be exact frozen canonical JSON')
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate model metadata field')
        result[key] = value
    return result


def closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('unknown or missing model public policy field')
    return value


def timestamp(value):
    if type(value) is not str:
        raise ValueError('model UTC timestamp must be a string')
    parsed = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if parsed.strftime('%Y-%m-%dT%H:%M:%SZ') != value:
        raise ValueError('noncanonical model UTC timestamp')
    return parsed


def raw_key(value):
    if type(value) is not str:
        raise ValueError('model public key must be canonical base64')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ValueError('model public key must be raw Ed25519')
    return raw


def strings(values, maximum):
    if type(values) is not list or not values or len(values) > maximum \
            or any(type(v) is not str or not v or v.strip() != v or len(v) > 256
                   or not all(32 <= ord(c) <= 126 for c in v) for v in values) \
            or values != sorted(set(values)):
        raise ValueError('model policy list must be bounded, nonempty and canonically ordered')


class Tree:
    """Retain every directory/member snapshot until all outputs are published."""
    def __init__(self, path, stack):
        self.values = {}
        self.directories = []
        self.total = 0
        self._walk(Path(path), '', stack, 0)

    def _walk(self, path, prefix, stack, depth):
        if depth > 8 or len(self.values) > 16384:
            raise ValueError('model public input tree exceeds bound')
        directory = stack.enter_context(public.Directory(path))
        self.directories.append(directory)
        for name in sorted(directory.names):
            member = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            relative = prefix + name
            if stat.S_ISDIR(member.st_mode):
                self._walk(path / name, relative + '/', stack, depth + 1)
            elif stat.S_ISREG(member.st_mode):
                value = directory.read(name, MAX_MEMBER)
                self.total += len(value)
                if self.total > MAX_TOTAL:
                    raise ValueError('model public metadata total exceeds bound')
                self.values[relative] = value
            else:
                raise ValueError('symlink or special member in model public inputs')

    def recheck(self):
        for directory in self.directories:
            directory.recheck()


def validate(root, values):
    required = {'model-roots.json', 'model-trust.json', 'catalog.json'}
    if not required <= values.keys():
        raise ValueError('model public inputs require complete root/trust/catalog group')
    policy = closed(document(values['model-roots.json']), ('schema_version', 'trust_domain',
                    'accepted_trust_policy_versions', 'accepted_catalog_policy_versions',
                    'roots', 'separated_key_sha256'))
    if type(policy['schema_version']) is not int or policy['schema_version'] != 1 \
            or policy['trust_domain'] != 'luma-models':
        raise ValueError('unsupported independently provisioned model root policy')
    for field in ('accepted_trust_policy_versions', 'accepted_catalog_policy_versions'):
        strings(policy[field], 32)
    separated = policy['separated_key_sha256']
    if type(separated) is not list or len(separated) > 1024 or separated != sorted(set(separated)):
        raise ValueError('model separated key digests must be bounded and ordered')
    for digest in separated:
        public.hexadecimal(digest, 32)
    if type(policy['roots']) is not list or not 1 <= len(policy['roots']) <= 32:
        raise ValueError('model root set must be finite and nonempty')
    roots = {}
    root_keys = set()
    for item in policy['roots']:
        closed(item, ('key_id', 'environment', 'trust_domain', 'public_key', 'not_before', 'not_after', 'revoked_at'))
        raw = raw_key(item['public_key'])
        anchor = RootTrustAnchor(item['key_id'], item['environment'], item['trust_domain'], raw,
                    timestamp(item['not_before']), timestamp(item['not_after']),
                    timestamp(item['revoked_at']) if item['revoked_at'] is not None else None)
        if anchor.trust_domain != 'luma-models' or anchor.key_id in roots or raw in root_keys:
            raise ValueError('model roots reuse key/ID or have a foreign trust domain')
        roots[anchor.key_id] = anchor
        root_keys.add(raw)
    prohibited = set(separated)
    for name in public.OTHER_KEYS:
        at = root / 'usr/share/luma-os' / name
        if at.exists() or at.is_symlink():
            with public.Directory(at.parent) as source:
                prohibited.add(public.sha(public.public_der(source.read(at.name, 4096))))
    for key in root_keys:
        if public.sha(public.SPKI + key) in prohibited:
            raise ValueError('model root reuses an existing OS/skill/domain key')
    trust = SignedTrustBundle.parse(values['model-trust.json'])
    raw_trust = document(values['model-trust.json'])
    anchor = roots.get(trust.root_key_id)
    if anchor is None or trust.environment != anchor.environment or trust.trust_domain != 'luma-models' \
            or trust.policy_version not in policy['accepted_trust_policy_versions'] \
            or trust.not_before < anchor.not_before or trust.not_after > anchor.not_after \
            or (anchor.revoked_at is not None and trust.not_after > anchor.revoked_at):
        raise ValueError('model bundle escapes independently provisioned root/policy bounds')
    public.verify(public.SPKI + anchor.public_key, canonical(raw_trust['bundle']), trust.signature)
    keys = {key.key_id: key for key in trust.keys}
    for key in keys.values():
        if key.public_key in root_keys or public.sha(public.SPKI + key.public_key) in prohibited:
            raise ValueError('model leaf reuses a root or OS/skill/domain key')
    with public.Directory(root / 'usr/share/luma-os') as directory:
        identity = json.loads(directory.read('release-identity.json', 4096), object_pairs_hook=unique)
        directory.recheck()
    envelope = CatalogSignatureEnvelope.parse(values['catalog-envelope.json']) if 'catalog-envelope.json' in values else None
    statement = envelope.statement if envelope else None
    catalog = parse_canonical_catalog(values['catalog.json'])
    if trust.environment != identity['environment']:
        raise ValueError('model public trust differs from immutable image environment')
    if statement and (statement.environment != trust.environment \
            or statement.release_id != identity['release'] or statement.catalog_id != catalog.catalog_id \
            or statement.catalog_sha256 != public.sha(values['catalog.json']) \
            or statement.policy_version not in policy['accepted_catalog_policy_versions'] \
            or not trust.not_before <= statement.signed_at < trust.not_after):
        raise ValueError('model catalog is not bound to this immutable image/root environment')
    # This is structural signature qualification at the declared instant, not
    # deployment clock evidence or verification of active assignment receipts.
    def signature(key_id, purpose, message, signature_bytes):
        key = keys.get(key_id)
        instant = statement.signed_at if statement else trust.issued_at
        if key is None or purpose not in {p.value for p in key.purposes} \
                or not key.not_before <= instant < key.not_after \
                or (key.revoked_at is not None and instant >= key.revoked_at):
            raise ValueError('model signing purpose/key is unavailable at signed catalog instant')
        public.verify(public.SPKI + key.public_key, message, signature_bytes)
    if statement:
        signature(statement.signer_key_id, 'model-profile-catalog-' + trust.environment,
                  canonical(document(values['catalog-envelope.json'])['statement']), envelope.signature)
    compiled = json.loads((REPO / 'native/image/model-catalog.json').read_bytes())
    native = {p['id']: p for p in compiled['models']}
    tuple_value = {'os_family': 'Linux', 'architecture': 'amd64', 'backend': 'llama.cpp',
                   'backend_version': 'b11100', 'device': 'cpu'}
    tuple_digest = public.sha(canonical(tuple_value))
    expected = set(required)
    if envelope: expected.add('catalog-envelope.json')
    for profile in catalog.profiles:
        if profile.kind == 'manual-only':
            continue
        p = profile.canonical_payload()
        n = native.get(p['profile_id'])
        if n is None:
            raise ValueError('model catalog requires unsupported compiled native profile')
        prefix = 'model-packs/' + p['model_pack_manifest_sha256'] + '/'
        expected.update((prefix + 'manifest.json', prefix + 'manifest.sig'))
        manifest = ModelManifest.parse(values[prefix + 'manifest.json'])
        m = manifest.document
        if public.sha(manifest.canonical_bytes) != p['model_pack_manifest_sha256']:
            raise ValueError('model pack is not its declared immutable digest')
        signature(manifest.signer_key_id, 'model-pack-manifest', manifest.canonical_bytes,
                  values[prefix + 'manifest.sig'])
        models = [b for b in manifest.blobs if b.role == 'model']
        size = sum(b.size_bytes for b in manifest.blobs)
        floor = size + n['bytes'] + RESERVE
        memory = lambda r: len(r) == 1 and r[0]['domain'] == 'host' and r[0]['bytes'] >= n['memory_max_bytes']
        installs = [i for i in manifest.installation_profiles if i.profile_id == p['profile_id']]
        if len(manifest.blobs) > 128 or len(models) != 1 or models[0].sha256 != n['sha256'] or models[0].size_bytes != n['bytes'] \
                or models[0].shard_index != 0 or tuple_value not in m['runtime_tuples'] \
                or p['runtime_tuple_sha256'] != tuple_digest or p['execution_mode'] != 'cpu' \
                or p['minimum_accelerator_memory_bytes'] != 0 or p['context_tokens'] != n['context_tokens'] \
                or p['minimum_host_ram_bytes'] < n['minimum_ram_bytes'] or p['install_bytes'] != size \
                or p['storage_peak_bytes'] < floor or not memory(p['load_reservations']) or not memory(p['serve_reservations']) \
                or p['minimum_host_ram_bytes'] <= max(p['load_reservations'][0]['bytes'], p['serve_reservations'][0]['bytes']) \
                or (p['parameter_total'], p['parameter_active_min'], p['parameter_active_max']) != (n['parameters'], n['active_parameters'], n['active_parameters']) \
                or m['model']['architecture'] != 'qwen3' or m['model']['quantization'] != 'Q4_K_M' \
                or m['model']['required_features'] != ['chat-completion', 'text-generation'] \
                or m['model']['source'] != n['url'] or manifest.total_parameters != n['parameters'] \
                or manifest.active_parameters_min != n['active_parameters'] or manifest.active_parameters_max != n['active_parameters'] \
                or manifest.maximum_context_tokens < n['context_tokens'] or manifest.license_use != 'approved' \
                or m['license']['identifier'] != n['license'] or len(installs) != 1:
            raise ValueError('model pack/catalog changes or understates compiled native tuple')
        install = installs[0]
        if install.runtime_tuple_sha256 != tuple_digest or install.execution_mode != 'cpu' \
                or install.minimum_accelerator_memory_bytes != 0 \
                or install.minimum_host_ram_bytes > p['minimum_host_ram_bytes'] \
                or install.minimum_model_storage_bytes > p['storage_peak_bytes'] \
                or install.maximum_context_tokens < n['context_tokens']:
            raise ValueError('model install profile does not match actual native execution')
        auxiliary = 0
        for blob in manifest.blobs:
            if blob.role == 'model':
                continue
            name = prefix + blob.path.as_posix()
            expected.add(name)
            data = values[name]
            auxiliary += len(data)
            if auxiliary > 64 * 1024 * 1024 or len(data) != blob.size_bytes or public.sha(data) != blob.sha256:
                raise ValueError('model public auxiliary blob exceeds bound or digest mismatch')
        levels = {'not-certified': (), 'execution-certified': ('execution',),
                  'interactive-certified': ('execution', 'interactive')}[p['certification_state']]
        if trust.environment == 'production':
            # Final-image/machine evidence is delivered after the immutable
            # image exists. Embedding it here would create a root-hash cycle.
            levels = ()
        for level in levels:
            cert_prefix = 'model-certifications/' + p['model_pack_manifest_sha256'] + '/' + level
            expected.update((cert_prefix + '.json', cert_prefix + '.sig'))
            record = CertificationRecord(**closed(document(values[cert_prefix + '.json']),
                     ('level', 'pack_manifest_sha256', 'runtime_tuple_sha256', 'evidence_sha256', 'signer_key_id')))
            if record.level != level or record.pack_manifest_sha256 != p['model_pack_manifest_sha256'] \
                    or record.runtime_tuple_sha256 != tuple_digest:
                raise ValueError('model certification changes exact pack/tuple/level')
            signature(record.signer_key_id, 'model-pack-' + level + '-certification',
                      record.canonical_bytes, values[cert_prefix + '.sig'])
    if set(values) != expected:
        raise ValueError('model public inputs include weights, unknown/private or undeclared members')
    return trust.environment


def provision(root, inputs=None):
    if inputs is None:
        return {'schema_version': 1, 'provided': False, 'activated': False}
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError('model image root must be an existing nonsymlink directory')
    with ExitStack() as stack:
        tree = Tree(inputs, stack)
        environment = validate(root, tree.values)
        outputs = {}
        for name, value in sorted(tree.values.items()):
            target = {'model-roots.json': 'model-roots.json', 'model-trust.json': 'models/initial-trust.json',
                      'catalog.json': 'models/catalog.json', 'catalog-envelope.json': 'models/catalog-envelope.json'}.get(name, name)
            relative = 'usr/share/luma-os/' + target
            tree.recheck()
            public.publish(root, relative, value)
            tree.recheck()
            outputs[relative] = public.sha(value)
        return {'schema_version': 1, 'provided': True, 'environment': environment,
                'activated': False, 'files': outputs}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--public-inputs', type=Path)
    args = parser.parse_args()
    print(json.dumps(provision(args.root, args.public_inputs), sort_keys=True))
