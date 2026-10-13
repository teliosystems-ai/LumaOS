"""Cross-domain public-key binding after all production groups are packaged."""
import base64
from pathlib import Path
import provision_public_trust as public


def raw_model_key(value):
    if not isinstance(value, str):
        raise ValueError('model key encoding differs')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ValueError('model key encoding differs')
    return public.SPKI + raw


def recheck_public_domains(root, out):
    import production_release
    root, out = Path(root), Path(out)
    values, report = production_release.load_inputs(out)
    share = root/'usr/share/luma-os'
    for name, expected in [('production-release-root.pub', values['production-release-root.pub']),
                           ('release.pub', report['release_public']),
                           ('admin-pcr-public.pem', report['pcr_public'])]:
        with public.Directory(share) as directory:
            if directory.read(name, 4096) != expected:
                raise ValueError('packaging changed independently provisioned OS/PCR root or leaf')
            directory.recheck()
    os_keys = {public.sha(report['root_der'])} | {
        public.sha(public.SPKI + bytes.fromhex(key['public_key_hex']))
        for key in report['signed_trust']['trust']['keys']}
    domains = {}
    with public.Directory(share/'skills') as directory:
        signed = public.document(directory.read('initial-trust.json', 32768))
        if signed['trust']['environment'] != 'production':
            raise ValueError('production assembly cannot package a laboratory skill trust group')
        domains['skills'] = {signed['trust']['root_sha256']} | {
            public.sha(public.SPKI + bytes.fromhex(key['public_key_hex']))
            for key in signed['trust']['keys']}
        directory.recheck()
    model_policy = share/'model-roots.json'
    if model_policy.exists() or model_policy.is_symlink():
        with public.Directory(share) as directory:
            policy = public.document(directory.read('model-roots.json', 65536))
            directory.recheck()
        with public.Directory(share/'models') as directory:
            signed = public.document(directory.read('initial-trust.json', 65536))
            if signed['bundle']['environment'] != 'production':
                raise ValueError('production assembly cannot package laboratory model trust')
            domains['models'] = {public.sha(raw_model_key(root['public_key'])) for root in policy['roots']} | {
                public.sha(raw_model_key(key['public_key'])) for key in signed['bundle']['keys']}
            directory.recheck()
    seen = set(os_keys)
    for keys in domains.values():
        if keys & seen:
            raise ValueError('production OS/skill/model roots or delegated signers share a key')
        seen.update(keys)
    return {'schema_version': 1, 'domains': sorted(['os-release', *domains]),
            'keys_are_distinct': True, 'activated': False}
