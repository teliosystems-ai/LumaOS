#!/usr/bin/env python3
"""Public-only, pinned external-custody phases for a native production image.

No private key, signing executor, approval, trusted-time assertion or QA pass is
accepted or generated. Response signatures must be supplied by external custody.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import re
import selectors
import time

import boot_policy
import desktop_policy
import provision_public_trust as public

_spec = importlib.util.spec_from_file_location('release_ceremony', Path(__file__).resolve().parents[2] / 'scripts/release_trust_ceremony.py')
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)
SLOTS = ('a', 'b', 'live', 'optical')
PE_NAMES = tuple(f'slot-{slot}.efi' for slot in SLOTS) + ('bootloader.efi',)
INPUTS = {'production-release-root.pub': 4096, 'release-trust.json': 32768,
          'release-signer.json': 4096, 'secureboot.pem': 16384, 'pcr-policy.pub': 4096}
IDENTITY_FIELDS = ('schema_version', 'release', 'sequence', 'environment', 'architecture', 'ubuntu', 'edition')


def canonical(value):
    return release.canonical(value)


def exact(data, fields):
    value = public.closed(public.document(data), fields)
    if canonical(value) != data:
        raise ValueError('production custody metadata must be exact canonical JSON')
    return value


def command(*args, input_bytes=None):
    if input_bytes is not None and (type(input_bytes) is not bytes or len(input_bytes) > 65536):
        raise ValueError('public verifier stdin exceeds its bound')
    process = subprocess.Popen([str(arg) for arg in args],
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + 120
    pending = memoryview(input_bytes or b'')
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, target in ((process.stdout, output), (process.stderr, errors)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, target)
            if process.stdin is not None:
                os.set_blocking(process.stdin.fileno(), False)
                if pending: selector.register(process.stdin, selectors.EVENT_WRITE, None)
                else: process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise ValueError('fixed public verifier exceeded its deadline')
                for key, _ in selector.select(min(remaining, 1)):
                    if key.data is None:
                        count = os.write(key.fd, pending[:32768]); pending = pending[count:]
                        if not pending: selector.unregister(key.fileobj); key.fileobj.close()
                    else:
                        data = os.read(key.fd, min(32768, 4 * 1024 * 1024 + 1 - len(output) - len(errors)))
                        if not data: selector.unregister(key.fileobj)
                        else:
                            key.data.extend(data)
                            if len(output) + len(errors) > 4 * 1024 * 1024:
                                raise ValueError('fixed public verifier output exceeds its streaming bound')
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining):
                raise ValueError('fixed public production verification tool refused')
        return bytes(output)
    finally:
        if process.poll() is None: process.kill()
        process.wait(timeout=5)
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None: pipe.close()


def rsa_public(pem):
    if not re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?', pem):
        raise ValueError('expected public-only RSA SPKI PEM')
    der = release.openssl(['pkey', '-pubin', '-in', '{0}', '-outform', 'DER'], [pem])
    # OpenSSL provides the exact PKCS#1 public representation; inspect integers
    # rather than trusting ambiguous human-readable key-size output.
    raw = release.openssl(['rsa', '-pubin', '-in', '{0}', '-RSAPublicKey_out', '-outform', 'DER'], [pem])
    def tlv(data, offset, tag):
        if offset >= len(data) or data[offset] != tag:
            raise ValueError('invalid DER public RSA structure')
        length = data[offset + 1]; offset += 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or offset + count > len(data) or data[offset] == 0:
                raise ValueError('invalid DER length')
            length = int.from_bytes(data[offset:offset + count], 'big'); offset += count
            if length < 128:
                raise ValueError('noncanonical DER length')
        end = offset + length
        if end > len(data):
            raise ValueError('truncated RSA public key')
        return data[offset:end], end
    body, end = tlv(raw, 0, 0x30)
    if end != len(raw):
        raise ValueError('trailing RSA public key data')
    modulus, offset = tlv(body, 0, 2)
    exponent, end = tlv(body, offset, 2)
    bits = int.from_bytes(modulus, 'big').bit_length()
    if end != len(body) or bits not in (3072, 4096) or int.from_bytes(exponent, 'big') != 65537:
        raise ValueError('production public RSA requires 3072/4096 bits and exponent 65537')
    return der, raw, bits


def public_inputs(values):
    if set(values) != set(INPUTS):
        raise ValueError('production public custody group is incomplete or contains unknown/private files')
    signer = exact(values['release-signer.json'], ('schema_version', 'signer'))
    if type(signer['schema_version']) is not int or signer['schema_version'] != 1:
        raise ValueError('unsupported production signer selector')
    release.identifier(signer['signer'])
    signed = exact(values['release-trust.json'], ('trust', 'signature_hex'))
    trust = release.validate_trust(signed['trust'])
    if trust['environment'] != 'production' or trust['version'] != 1:
        raise ValueError('initial production image requires production genesis trust')
    root = public.public_der(values['production-release-root.pub'])
    if public.sha(root) != trust['root_sha256']:
        raise ValueError('independent production release root does not match signed trust')
    public.verify(root, canonical(trust), public.hexadecimal(signed['signature_hex'], 64))
    leaf = [key for key in trust['keys'] if key['id'] == signer['signer'] and not key['revoked']]
    if len(leaf) != 1:
        raise ValueError('selected production release signer is missing or revoked')
    pcr_der, pcr_raw, bits = rsa_public(values['pcr-policy.pub'])
    if bits != 3072:
        raise ValueError('installed approved PCR policy uses an exact RSA3072 public key')
    certificate = values['secureboot.pem']
    if not re.fullmatch(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?', certificate):
        raise ValueError('Secure Boot input must contain one public X509 certificate')
    cert_der = release.openssl(['x509', '-in', '{0}', '-outform', 'DER'], [certificate])
    sb_pem = release.openssl(['x509', '-in', '{0}', '-pubkey', '-noout'], [certificate])
    sb_der, _, _ = rsa_public(sb_pem)
    if sb_der == pcr_der:
        raise ValueError('PCR and Secure Boot custody keys must be separate')
    return {'signer': signer['signer'], 'signed_trust': signed,
            'release_public': b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(public.SPKI + bytes.fromhex(leaf[0]['public_key_hex'])) + b'\n-----END PUBLIC KEY-----\n',
            'pcr_public': values['pcr-policy.pub'], 'secureboot_der': cert_der,
            'root_der': root, 'pcr_fingerprint': public.sha(pcr_raw),
            'fingerprints': {name: public.sha(data) for name, data in sorted(values.items())}}


def load_inputs(out):
    with public.Directory(Path(out) / 'production-public') as source:
        if source.names != set(INPUTS):
            raise ValueError('retained public custody inventory changed')
        values = {name: source.read(name, limit) for name, limit in INPUTS.items()}
        report = public_inputs(values)
        source.recheck()
        return values, report


def new_group(path, values):
    path = Path(path)
    path.mkdir(mode=0o700)
    try:
        for name, data in values.items():
            if Path(name).name != name:
                raise ValueError('custody output requires exact basename')
            release.exclusive_write(path / name, data)
    except BaseException:
        # Retained partial groups are explicit uncertain state, never discarded
        # or overwritten by a retry with new inputs.
        raise


def validate_public_inputs(root, inputdir, identity, out):
    root, out = Path(root), Path(out)
    if (out / 'production-public').exists() or (out / 'production-public').is_symlink():
        raise FileExistsError('retained production public group already exists; preserve it')
    public.closed(identity, IDENTITY_FIELDS)
    if identity['environment'] != 'production' or type(identity['schema_version']) is not int or identity['schema_version'] != 1 or identity['architecture'] != 'amd64' or identity['ubuntu'] != '24.04' or identity['edition'] not in ('headless', 'desktop'):
        raise ValueError('invalid production immutable image identity')
    release.identifier(identity['release']); release.number(identity['sequence'], 1, 2**63 - 1)
    with public.Directory(inputdir) as source:
        if source.names != set(INPUTS):
            raise ValueError('closed production public-input inventory differs')
        values = {name: source.read(name, limit) for name, limit in INPUTS.items()}
        report = public_inputs(values)
        source.recheck()
        # Existing OS/skill/model packaging adapters enforce their own full
        # signed schemas. This explicit material inventory prevents either
        # delegated keys or roots from crossing the OS boundary.
        prohibited = set()
        share = root / 'usr/share/luma-os'
        for name in public.OTHER_KEYS:
            path = share / name
            if path.exists() or path.is_symlink():
                with public.Directory(path.parent) as current:
                    prohibited.add(public.sha(public.public_der(current.read(path.name, 4096))))
        os_keys = {public.sha(report['root_der'])} | {public.sha(public.SPKI + bytes.fromhex(k['public_key_hex'])) for k in report['signed_trust']['trust']['keys']}
        if os_keys & prohibited:
            raise ValueError('production OS root/leaf reuses a packaged foreign-domain key')
        new_group(out / 'production-public', values)
        public.publish(root, 'usr/share/luma-os/production-release-root.pub', values['production-release-root.pub'])
        public.publish(root, 'usr/share/luma-os/release.pub', report['release_public'])
        public.publish(root, 'usr/share/luma-os/admin-pcr-public.pem', report['pcr_public'])
        source.recheck()
    return {'schema_version': 1, 'signer': report['signer'], 'public_inputs': report['fingerprints'],
            'pcr_fingerprint': report['pcr_fingerprint'], 'secureboot_sha256': public.sha(report['secureboot_der']),
            'activated': False, 'custody_performed': False}


def request_group(out, phase, values, metadata):
    request = {'schema_version': 1, 'environment': 'production', 'phase': phase,
               **metadata, 'files': {name: public.sha(data) for name, data in sorted(values.items())}}
    data = canonical(request)
    new_group(Path(out) / ('production-' + phase + '-request'), {'request.json': data, **values})
    return {'phase': phase, 'request_sha256': public.sha(data), 'request': request, 'activated': False}


def read_request(out, phase):
    with public.Directory(Path(out) / ('production-' + phase + '-request')) as source:
        data = source.read('request.json', 65536)
        request = public.document(data)
        fields = {'schema_version', 'environment', 'phase', 'files'} | {
            'pcr': {'identity', 'public_inputs', 'pcr_fingerprint', 'policies', 'signature_algorithm'},
            'pe': {'prior_request_sha256', 'identity', 'public_inputs', 'certificate_sha256'},
            'release': {'signer', 'public_inputs', 'signature_algorithm'},
        }[phase]
        public.closed(request, fields)
        if canonical(request) != data or type(request.get('schema_version')) is not int or request.get('schema_version') != 1 or request.get('environment') != 'production' or request.get('phase') != phase or type(request.get('files')) is not dict:
            raise ValueError('retained production request identity differs')
        expected = {'pcr': {*PE_NAMES, 'production-build.json', 'source-lock.json',
                            'a-0.policy', 'a-1.policy', 'b-0.policy', 'b-1.policy'},
                    'pe': {*PE_NAMES, 'production-build.json', 'source-lock.json'},
                    'release': {'release.json'}}[phase]
        if set(request['files']) != expected:
            raise ValueError('retained production request contains unknown/private or missing phase members')
        if phase in ('pcr', 'release') and request['signature_algorithm'] != {
                'pcr': 'RSA3072-PKCS1v1.5-SHA256', 'release': 'Ed25519-raw-message'}[phase]:
            raise ValueError('retained production request signature algorithm differs')
        if source.names != {'request.json', *request['files']}:
            raise ValueError('retained production request inventory changed')
        values = {name: source.read(name, 256 * 1024 * 1024) for name in request['files']}
        if any(public.sha(value) != request['files'][name] for name, value in values.items()):
            raise ValueError('retained production request bytes changed')
        source.recheck()
        return request, values, public.sha(data)


def measure(image):
    sections = boot_policy.read_sections(image)
    with tempfile.TemporaryDirectory(prefix='luma-production-measure-') as temporary:
        args = ['/usr/lib/systemd/systemd-measure', 'calculate', '--bank=sha256', '--json=short']
        args += ['--phase=' + phase for phase in boot_policy.PHASES]
        for name in boot_policy.SECTIONS:
            if '.' + name in sections:
                path = Path(temporary) / name
                release.exclusive_write(path, sections['.' + name])
                args.append('--' + name + '=' + str(path))
        observed = boot_policy.closed_json(command(*args))
        if set(observed) != {'sha256'} or len(observed['sha256']) != 2:
            raise ValueError('unexpected installed PCR measurement inventory')
        if {value['phase'] for value in observed['sha256']} != set(boot_policy.PHASES) or any(value['pcr'] != 11 for value in observed['sha256']):
            raise ValueError('measured PCR bank/phase differs')
        return sections, [{'phase': value['phase'], 'policy': boot_policy.policy_digest(value['hash'])} for value in observed['sha256']]


def check_slot(sections, slot, pcr_public):
    cmdline = sections.get('.cmdline', b'').rstrip(b'\0').decode('ascii').split()
    for prefix, value in [('luma.slot=', 'live' if slot == 'optical' else slot), ('luma.mode=', 'live' if slot in ('live','optical') else 'installed')]:
        if [word for word in cmdline if word.startswith(prefix)] != [prefix + value]:
            raise ValueError('production unsigned UKI slot/mode differs')
    if [word for word in cmdline if word.startswith('luma.media=')] != (['luma.media=optical'] if slot == 'optical' else []):
        raise ValueError('production unsigned UKI transport differs')
    if slot in ('live','optical'):
        if '.pcrsig' in sections or '.pcrpkey' in sections:
            raise ValueError('live production media cannot carry installed PCR approval')
    elif sections.get('.pcrpkey') != pcr_public:
        raise ValueError('unsigned installed UKI has the wrong public PCR signer')


def build_checkpoint(out):
    with public.Directory(out) as artifacts:
        raw = artifacts.read('production-build.json', 65536)
        value = public.closed(public.document(raw), ('schema_version', 'identity', 'root_hash', 'kernel', 'source_lock_sha256', 'initrd_policy', 'desktop'))
        public.closed(value['identity'], IDENTITY_FIELDS)
        if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['identity']['environment'] != 'production':
            raise ValueError('unsupported original production build checkpoint')
        public.hexadecimal(value['root_hash'], 32); public.hexadecimal(value['source_lock_sha256'], 32)
        if type(value['kernel']) is not str or not re.fullmatch('[A-Za-z0-9_.+-]{1,128}', value['kernel']):
            raise ValueError('production kernel identity differs')
        source = artifacts.read('source-lock.json', 4 * 1024 * 1024)
        if public.sha(source) != value['source_lock_sha256']:
            raise ValueError('original production source identity changed')
        artifacts.recheck()
        return value, raw, source


def expected_cmdline(checkpoint, slot):
    return boot_policy.command_line(checkpoint['root_hash'],slot,checkpoint['identity']['edition'])


def check_build_sections(sections, checkpoint, slot):
    if sections.get('.cmdline', b'').rstrip(b'\0') != expected_cmdline(checkpoint, slot).encode('ascii'):
        raise ValueError('production UKI kernel policy/root/desktop command line differs')
    if sections.get('.uname', b'').rstrip(b'\0') != checkpoint['kernel'].encode('ascii'):
        raise ValueError('production UKI original kernel identity differs')
    desktop_policy.verify_boot_target(sections['.cmdline'], checkpoint['identity']['edition'], 'live' if slot in ('live','optical') else 'installed')


def prepare_pcr(out, root):
    out, root = Path(out), Path(root)
    values, report = load_inputs(out)
    with public.Directory(root / 'usr/share/luma-os') as image:
        identity = public.closed(public.document(image.read('release-identity.json', 4096)), IDENTITY_FIELDS)
        image.recheck()
    if identity['environment'] != 'production':
        raise ValueError('PCR request must bind an immutable production root')
    checkpoint, build_raw, source_raw = build_checkpoint(out)
    if checkpoint['identity'] != identity:
        raise ValueError('original build and immutable production root identities differ')
    files, policies = {'production-build.json': build_raw, 'source-lock.json': source_raw}, {}
    kernel = None
    unsigned = out / 'production-unsigned'
    with public.Directory(unsigned) as images:
        if images.names != set(PE_NAMES):
            raise ValueError('unsigned production boot inventory differs')
        for slot in SLOTS:
            name = f'slot-{slot}.efi'; files[name] = images.read(name, 256 * 1024 * 1024)
            sections = boot_policy.read_sections(unsigned / name)
            check_slot(sections, slot, report['pcr_public'])
            check_build_sections(sections, checkpoint, slot)
            observed_kernel = sections.get('.linux', b'')
            if not observed_kernel or kernel is not None and observed_kernel != kernel:
                raise ValueError('production boot slots do not contain one exact original kernel')
            kernel = observed_kernel
            if '.pcrsig' in sections:
                raise ValueError('initial external PCR request requires unsigned policy inputs')
            if slot in ('a','b'):
                _, policies[slot] = measure(unsigned / name)
                for index, policy in enumerate(policies[slot]):
                    files[f'{slot}-{index}.policy'] = bytes.fromhex(policy['policy'])
        files['bootloader.efi'] = images.read('bootloader.efi', 16 * 1024 * 1024)
        images.recheck()
    return request_group(out, 'pcr', files, {'identity': identity, 'public_inputs': report['fingerprints'],
                         'pcr_fingerprint': report['pcr_fingerprint'], 'policies': policies,
                         'signature_algorithm': 'RSA3072-PKCS1v1.5-SHA256'})


def accept_pcr(out, responsedir):
    out = Path(out); values, report = load_inputs(out)
    request, files, pin = read_request(out, 'pcr')
    if request['public_inputs'] != report['fingerprints']:
        raise ValueError('PCR public custody group changed')
    with public.Directory(responsedir) as responses:
        if responses.names != {'pcr-response.json'}:
            raise ValueError('unexpected PCR custody response files')
        response = exact(responses.read('pcr-response.json', 16384), ('schema_version', 'request_sha256', 'signatures'))
        if type(response['schema_version']) is not int or response['schema_version'] != 1 or response['request_sha256'] != pin or set(response['signatures']) != {'a', 'b'}:
            raise ValueError('PCR response does not bind this exact request')
        approved = {}; output = out / 'production-pcr-approved'; output.mkdir(mode=0o700)
        for slot in SLOTS:
            name = f'slot-{slot}.efi'; image = output / name
            release.exclusive_write(image, files[name])
            if slot in ('a','b'):
                signatures = response['signatures'][slot]
                if type(signatures) is not list or len(signatures) != len(request['policies'][slot]):
                    raise ValueError('PCR response has the wrong phase count')
                records = []
                for index, policy in enumerate(request['policies'][slot]):
                    raw = base64.b64decode(signatures[index], validate=True)
                    if len(raw) != 384 or base64.b64encode(raw).decode() != signatures[index]:
                        raise ValueError('PCR signature is not canonical raw RSA3072')
                    release.openssl(['dgst', '-sha256', '-verify', '{0}', '-signature', '{1}', '{2}'], [report['pcr_public'], raw, files[f'{slot}-{index}.policy']])
                    records.append({'pcrs': [11], 'pkfp': report['pcr_fingerprint'], 'pol': policy['policy'], 'sig': signatures[index]})
                policy_path = output / f'{slot}.pcrsig'
                release.exclusive_write(policy_path, canonical({'sha256': records}))
                command('/usr/bin/objcopy', '--add-section', '.pcrsig=' + str(policy_path),
                        '--set-section-flags', '.pcrsig=contents,alloc,load,readonly,data', image)
                before = boot_policy.read_sections(out / 'production-pcr-request' / name)
                after = boot_policy.read_sections(image)
                if set(after) != set(before) | {'.pcrsig'} or any(after[k] != v for k, v in before.items()):
                    raise ValueError('PCR insertion changed an original UKI section')
                _, actual = measure(image)
                if actual != request['policies'][slot]:
                    raise ValueError('PCR insertion changed actual measured policies')
            approved[name] = image.read_bytes()
        approved['bootloader.efi'] = files['bootloader.efi']
        approved['production-build.json'] = files['production-build.json']
        approved['source-lock.json'] = files['source-lock.json']
        responses.recheck()
    return request_group(out, 'pe', approved, {'prior_request_sha256': pin, 'identity': request['identity'],
                         'public_inputs': report['fingerprints'], 'certificate_sha256': public.sha(report['secureboot_der'])})


def pe_signature_offsets(data):
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('expected exact PE image')
    header = struct.unpack_from('<I', data, 60)[0]
    if header < 64 or header + 24 > len(data) or data[header:header + 4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    optional = header + 24
    size = struct.unpack_from('<H', data, header + 20)[0]
    if optional + size > len(data) or size < 160 or struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('production supports exact PE32+ only')
    security = optional + 112 + 8 * 4
    count = struct.unpack_from('<I', data, optional + 108)[0]
    if count < 5 or security + 8 > optional + size:
        raise ValueError('PE security directory is unavailable')
    return optional + 64, security, struct.unpack_from('<II', data, security)


def verify_pe_preservation(unsigned, signed):
    checksum, security, (old_offset, old_size) = pe_signature_offsets(unsigned)
    new_checksum, new_security, (offset, size) = pe_signature_offsets(signed)
    if old_offset or old_size or (checksum, security) != (new_checksum, new_security):
        raise ValueError('request must be unsigned and preserve exact PE header placement')
    if offset % 8 or size < 8 or offset < len(unsigned) or offset - len(unsigned) > 7 or offset + size != len(signed):
        raise ValueError('signed PE certificate table is not one bounded appended extent')
    if any(signed[len(unsigned):offset]):
        raise ValueError('signed PE added nonzero unhashed alignment bytes')
    before, after = bytearray(unsigned), bytearray(signed[:len(unsigned)])
    for begin, end in [(checksum, checksum + 4), (security, security + 8)]:
        before[begin:end] = bytes(end - begin); after[begin:end] = bytes(end - begin)
    if before != after:
        raise ValueError('external Secure Boot signing changed original executable bytes')
    length, revision, kind = struct.unpack_from('<IHH', signed, offset)
    if length < 8 or length > size or (length + 7) & ~7 != size or revision != 0x200 or kind != 2 or any(signed[offset + length:]):
        raise ValueError('signed PE certificate inventory differs')


def accept_pe(out, responsedir):
    out = Path(out); values, report = load_inputs(out)
    request, files, pin = read_request(out, 'pe')
    if request['public_inputs'] != report['fingerprints']:
        raise ValueError('Secure Boot public custody group changed')
    with public.Directory(responsedir) as response:
        if response.names != {'pe-response.json', *PE_NAMES}:
            raise ValueError('Secure Boot response has unknown/private or missing artifacts')
        metadata = exact(response.read('pe-response.json', 16384), ('schema_version', 'request_sha256', 'files'))
        if metadata['schema_version'] != 1 or type(metadata['schema_version']) is not int or metadata['request_sha256'] != pin or set(metadata['files']) != set(PE_NAMES):
            raise ValueError('Secure Boot response is not bound to this exact request')
        signed = {}
        for name in PE_NAMES:
            data = response.read(name, 256 * 1024 * 1024 if name.startswith('slot-') else 16 * 1024 * 1024)
            if public.sha(data) != metadata['files'][name]:
                raise ValueError('Secure Boot response hash mismatch')
            verify_pe_preservation(files[name], data)
            command('/usr/bin/sbverify', '--cert', out / 'production-public/secureboot.pem', Path(responsedir) / name)
            if name.startswith('slot-'):
                boot_policy.verify_uki(Path(responsedir) / name, name[5:-4], report['pcr_public'], out / 'production-public/secureboot.pem')
            signed[name] = data
        response.recheck()
        for name, data in signed.items():
            public.publish(out, name, data)
        public.publish(out, 'secureboot.cer', report['secureboot_der'])
    return {'schema_version': 1, 'phase': 'pe-verified', 'request_sha256': pin,
            'files': {name: public.sha(data) for name, data in signed.items()},
            'production_signatures_verified': True, 'custody_verified': False, 'activated': False}


def artifact_hash(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory.fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError('production artifact is not bounded regular single-link bytes')
        digest = hashlib.sha256(); total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            total += len(chunk)
            if total > maximum: raise ValueError('production artifact grew beyond its bound')
            digest.update(chunk)
        if total != before.st_size or public.identity(before) != public.identity(os.fstat(fd)) or public.identity(before) != public.identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)):
            raise ValueError('production artifact changed during verification')
        return {'name': name, 'bytes': total, 'sha256': digest.hexdigest()}
    finally:
        os.close(fd)


def check_manifest_artifacts(out, manifest):
    release.validate_manifest(manifest)
    if manifest['environment'] != 'production':
        raise ValueError('production release ceremony refuses laboratory metadata')
    with public.Directory(out) as directory:
        for artifact in manifest['artifacts']:
            maximum = 32 * 1024**3 if artifact['name'] == 'root.ext4' else 512 * 1024**2 if artifact['name'] == 'root.verity' else 256 * 1024**2 if artifact['name'].startswith('slot-') else 16 * 1024**2 if artifact['name'] == 'bootloader.efi' else 16384
            if artifact_hash(directory, artifact['name'], maximum) != artifact:
                raise ValueError('signed release manifest does not match actual final artifact bytes')
        directory.recheck()
    command('/usr/sbin/veritysetup', 'verify', Path(out) / 'root.ext4', Path(out) / 'root.verity', manifest['root_hash'])


def prepare_release(out, manifestbytes):
    out = Path(out); values, report = load_inputs(out)
    manifest = release.validate_manifest(release.parse(manifestbytes))
    pe_request, _, _ = read_request(out, 'pe')
    if {field: manifest[field] for field in IDENTITY_FIELDS} != pe_request['identity']:
        raise ValueError('release changes the exact immutable identity reviewed for Secure Boot')
    check_manifest_artifacts(out, manifest)
    checkpoint, _, _ = build_checkpoint(out)
    if checkpoint['identity'] != pe_request['identity'] or checkpoint['root_hash'] != manifest['root_hash']:
        raise ValueError('final release changed original build identity/root hash')
    for slot in SLOTS:
        record = boot_policy.verify_uki(out / f'slot-{slot}.efi', slot, report['pcr_public'], out / 'production-public/secureboot.pem')
        sections = boot_policy.read_sections(out / f'slot-{slot}.efi')
        check_build_sections(sections, checkpoint, slot)
        cmdline = sections['.cmdline'].rstrip(b'\0').decode('ascii').split()
        if [word for word in cmdline if word.startswith('roothash=')] != ['roothash=' + manifest['root_hash']]:
            raise ValueError('signed UKI root does not match final release verity identity')
        if record['slot'] != slot:
            raise ValueError('signed release slot inventory differs')
    command('/usr/bin/sbverify', '--cert', out / 'production-public/secureboot.pem', out / 'bootloader.efi')
    if (out / 'secureboot.cer').read_bytes() != report['secureboot_der']:
        raise ValueError('release certificate differs from independent public custody')
    return request_group(out, 'release', {'release.json': manifestbytes}, {'signer': report['signer'],
                         'public_inputs': report['fingerprints'], 'signature_algorithm': 'Ed25519-raw-message'})


def accept_release(out, responsedir):
    out = Path(out); values, report = load_inputs(out)
    request, files, pin = read_request(out, 'release')
    if request['public_inputs'] != report['fingerprints'] or request['signer'] != report['signer']:
        raise ValueError('release custody input changed')
    with public.Directory(responsedir) as response:
        if response.names != {'release-response.json', 'release.sig'}:
            raise ValueError('release response contains unknown/private files')
        metadata = exact(response.read('release-response.json', 4096), ('schema_version', 'request_sha256'))
        if type(metadata['schema_version']) is not int or metadata['schema_version'] != 1 or metadata['request_sha256'] != pin:
            raise ValueError('release signature response does not bind exact request')
        signature = response.read('release.sig', 64)
        release.signed_release(files['release.json'], signature, report['signer'], report['signed_trust'])
        check_manifest_artifacts(out, release.parse(files['release.json']))
        response.recheck()
        public.publish(out, 'release.json', files['release.json'])
        public.publish(out, 'release.sig', signature)
        public.publish(out, 'release-trust.json', values['release-trust.json'])
    return {'schema_version': 1, 'phase': 'release-verified', 'request_sha256': pin,
            'release_sha256': public.sha(files['release.json']), 'production_signatures_verified': True,
            'custody_verified': False, 'native_qualification': False, 'activated': False}


def verify_complete(out):
    """Reconstruct the actual entire public chain, never trust a phase receipt."""
    out = Path(out); values, report = load_inputs(out)
    pcr_request, pcr_files, pcr_pin = read_request(out, 'pcr')
    pe_request, pe_files, pe_pin = read_request(out, 'pe')
    release_request, release_files, release_pin = read_request(out, 'release')
    for request in (pcr_request, pe_request, release_request):
        if request['public_inputs'] != report['fingerprints']:
            raise ValueError('complete production public custody pins differ')
    if pe_request['prior_request_sha256'] != pcr_pin or pe_request['identity'] != pcr_request['identity']:
        raise ValueError('complete production PCR/Secure Boot chain differs')
    checkpoint, build_raw, source_raw = build_checkpoint(out)
    if pcr_files['production-build.json'] != build_raw or pe_files['production-build.json'] != build_raw or pcr_files['source-lock.json'] != source_raw or pe_files['source-lock.json'] != source_raw or checkpoint['identity'] != pcr_request['identity']:
        raise ValueError('complete production build/source/kernel/desktop pins changed')
    with public.Directory(out) as artifacts:
        raw = artifacts.read('release.json', 65536)
        signature = artifacts.read('release.sig', 64)
        if artifacts.read('release-trust.json', 32768) != values['release-trust.json'] or raw != release_files['release.json']:
            raise ValueError('complete production manifest/trust changed')
        manifest = release.signed_release(raw, signature, report['signer'], report['signed_trust'])['manifest']
        if {field: manifest[field] for field in IDENTITY_FIELDS} != pe_request['identity']:
            raise ValueError('complete signed release has another immutable image identity')
        if manifest['root_hash'] != checkpoint['root_hash']:
            raise ValueError('complete signed release changed the original root hash')
        for name in PE_NAMES:
            signed = artifacts.read(name, 256 * 1024**2 if name.startswith('slot-') else 16 * 1024**2)
            verify_pe_preservation(pe_files[name], signed)
            command('/usr/bin/sbverify', '--cert', out / 'production-public/secureboot.pem', out / name)
            if name.startswith('slot-'):
                slot = name[5:-4]
                boot_policy.verify_uki(out / name, slot, report['pcr_public'], out / 'production-public/secureboot.pem')
                before = boot_policy.read_sections(out / 'production-pcr-request' / name)
                after = boot_policy.read_sections(out / name)
                check_build_sections(after, checkpoint, slot)
                if slot in ('live','optical'):
                    if before != after: raise ValueError('live production UKI measured sections changed')
                elif set(after) != set(before) | {'.pcrsig'} or any(after[k] != v for k, v in before.items()):
                    raise ValueError('installed production UKI original measured contents changed')
                words = after['.cmdline'].rstrip(b'\0').decode('ascii').split()
                if [word for word in words if word.startswith('roothash=')] != ['roothash=' + manifest['root_hash']]:
                    raise ValueError('production UKI differs from exact final root hash')
            elif pe_files[name] != pcr_files[name]:
                raise ValueError('original production bootloader changed between custody phases')
        if artifacts.read('secureboot.cer', 16384) != report['secureboot_der']:
            raise ValueError('complete production Secure Boot certificate changed')
        artifacts.recheck()
    check_manifest_artifacts(out, manifest)
    return {'schema_version': 1, 'release': manifest['release'], 'sequence': manifest['sequence'],
            'release_sha256': public.sha(raw), 'pcr_request_sha256': pcr_pin,
            'pe_request_sha256': pe_pin, 'release_request_sha256': release_pin,
            'production_signatures_verified': True, 'custody_verified': False,
            'native_qualification': False, 'activated': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='phase', required=True)
    for name in ('accept-pcr', 'accept-pe', 'accept-release'):
        p = commands.add_parser(name); p.add_argument('--out', type=Path, required=True); p.add_argument('--response', type=Path, required=True)
    p = commands.add_parser('prepare-pcr'); p.add_argument('--out', type=Path, required=True); p.add_argument('--root', type=Path, required=True)
    p = commands.add_parser('prepare-release'); p.add_argument('--out', type=Path, required=True); p.add_argument('--manifest', type=Path, required=True)
    p = commands.add_parser('verify-complete'); p.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.phase == 'prepare-pcr': result = prepare_pcr(args.out, args.root)
    elif args.phase == 'prepare-release': result = prepare_release(args.out, release.read(args.manifest, 65536))
    elif args.phase == 'verify-complete': result = verify_complete(args.out)
    else: result = globals()[args.phase.replace('-', '_')](args.out, args.response)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
