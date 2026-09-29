"""Laboratory UKI PCR policy construction and independent artifact checks.

Build-time only. Does not enroll a TPM, approve production keys or authorize
Admin. Private PCR keys stay in the builder's dedicated private key volume.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

PHASES = ('enter-initrd:leave-initrd:sysinit',
          'enter-initrd:leave-initrd:sysinit:ready')
SECTIONS = ('linux', 'osrel', 'cmdline', 'initrd', 'splash', 'dtb', 'uname', 'sbat', 'pcrpkey')
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'SYSTEMD_LOG_LEVEL': 'err'}


def command(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True,
                          timeout=120, env=ENV, **kwargs).stdout


def private(path, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ValueError('PCR key custody path must be private, owned and not linked')


def prepare_lab_key(directory):
    """Keep a stable separate RSA signer; never overwrite an existing key."""
    private(directory, directory=True)
    key = directory / 'pcr-policy.key'
    try:
        key.lstat()
    except FileNotFoundError:
        # The exclusive temporary file is private even under a permissive umask.
        fd, filename = tempfile.mkstemp(prefix='.pcr-policy-', dir=directory)
        os.close(fd)
        candidate = Path(filename)
        try:
            command('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                    'rsa_keygen_bits:3072', '-out', candidate)
            with candidate.open('rb') as stream:
                os.fsync(stream.fileno())
            os.link(candidate, key)  # exclusive publication; collision refuses
        finally:
            candidate.unlink()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    private(key)
    public = command('openssl', 'rsa', '-in', key, '-pubout')
    if not 1 <= len(public) <= 4096:
        raise ValueError('PCR public key outside bound')
    return key, public


def signing_arguments(slot, key, public):
    if slot not in ('a', 'b', 'live'):
        raise ValueError('unknown boot slot')
    if slot == 'live':
        # Installer/recovery media must not implicitly unlock installed Admin.
        return []
    return ['--pcr-private-key', str(key), '--pcr-public-key', str(public),
            '--pcrpkey', str(public), '--pcr-banks', 'sha256',
            '--phases', ','.join(PHASES)]


def verify_initrd(initrd):
    listing = command('lsinitrd', initrd).decode('utf-8')
    paths = {line.split(' -> ', 1)[0].split()[-1].lstrip('./')
             for line in listing.splitlines() if line.split()}
    required = {'usr/lib/systemd/systemd-pcrextend',
                'usr/lib/systemd/system/systemd-pcrphase-initrd.service',
                'usr/lib/systemd/system/initrd.target.wants/systemd-pcrphase-initrd.service',
                'etc/udev/rules.d/99-luma-tpm.rules'}
    if not required <= paths or not any('/libtss2-esys.so.' in path for path in paths):
        raise ValueError('initrd lacks PCR phase helper, unit, activation, TPM rules or library')
    expected_rules = (Path(__file__).parent/'overlay/etc/udev/rules.d/99-luma-tpm.rules').read_bytes()
    if command('lsinitrd', '--file', 'etc/udev/rules.d/99-luma-tpm.rules', initrd) != expected_rules:
        raise ValueError('initrd TPM ownership rules differ from image policy')
    return {'phase_module': 'luma-pcrphase', 'required_paths': sorted(required)}


def policy_digest(pcr):
    if len(pcr) != 64 or any(c not in '0123456789abcdef' for c in pcr):
        raise ValueError('noncanonical SHA256 PCR')
    # TPM2 PolicyPCR: zero policy || command || TPML selection || hash(PCRs).
    # Fixed SHA256 bank, sole PCR11, three-byte selection. No TPM secret here.
    selection = bytes.fromhex('0000017f00000001000b03000800')
    return hashlib.sha256(bytes(32) + selection + hashlib.sha256(bytes.fromhex(pcr)).digest()).hexdigest()


def closed_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate PCR policy JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def read_sections(image):
    # Packaged dependency of ukify; do not require it on the Windows source lane.
    import pefile
    info = image.lstat()
    if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 256 * 1024 * 1024:
        raise ValueError('UKI must be a bounded regular file')
    result = {}
    with pefile.PE(str(image), fast_load=True) as pe:
        for section in pe.sections:
            name = section.Name.rstrip(b'\0').decode('ascii')
            if name in result:
                raise ValueError('duplicate UKI section')
            size = section.Misc_VirtualSize
            if size > section.SizeOfRawData:
                if name in {'.' + s for s in SECTIONS} | {'.pcrsig'}:
                    raise ValueError('truncated measured UKI section')
                continue
            result[name] = section.get_data()[:size]
    return result


def verify_uki(image, slot, expected_public, certificate):
    """Verify PE signature, embedded signer, signatures AND measured contents.

    Independently supplied public key/certificate are required. This is a
    builder check, not runtime release/custody admission of arbitrary files.
    """
    if slot not in ('a', 'b', 'live'):
        raise ValueError('unknown boot slot')
    sections = read_sections(image)
    command('sbverify', '--cert', certificate, image)
    cmdline = sections.get('.cmdline', b'').rstrip(b'\0').decode('ascii').split()
    mode = 'live' if slot == 'live' else 'installed'
    for prefix, value in [('luma.slot=', slot), ('luma.mode=', mode)]:
        if [word for word in cmdline if word.startswith(prefix)] != [prefix + value]:
            raise ValueError('UKI command line does not match expected slot/mode')
    if slot == 'live':
        if '.pcrsig' in sections or '.pcrpkey' in sections:
            raise ValueError('live media must not carry installed Admin PCR approval')
        return {'slot': slot, 'pcr_approval': False}
    if sections.get('.pcrpkey') != expected_public:
        raise ValueError('embedded PCR signer differs from expected public key')
    raw = sections.get('.pcrsig', b'')
    if not 1 <= len(raw) <= 16384:
        raise ValueError('missing/oversized PCR signatures')
    signatures = closed_json(raw)
    if (not isinstance(signatures, dict) or set(signatures) != {'sha256'}
            or not isinstance(signatures['sha256'], list)
            or len(signatures['sha256']) != len(PHASES)):
        raise ValueError('unexpected PCR banks or phase count')
    with tempfile.TemporaryDirectory(prefix='luma-uki-verify-') as folder:
        directory = Path(folder)
        args = ['/usr/lib/systemd/systemd-measure', 'calculate', '--bank=sha256', '--json=short']
        for phase in PHASES:
            args.append('--phase=' + phase)
        for name in SECTIONS:
            value = sections.get('.' + name)
            if value is not None:
                path = directory / name
                path.write_bytes(value)
                args.append('--' + name + '=' + str(path))
        measured = closed_json(command(*args))
        values = measured['sha256']
        if (len(values) != len(PHASES) or {v['phase'] for v in values} != set(PHASES)
                or any(v['pcr'] != 11 for v in values)):
            raise ValueError('unexpected measured PCR phase inventory')
        policies = {policy_digest(v['hash']) for v in values}
        public = directory / 'pcrpkey'
        fingerprint = hashlib.sha256(command('openssl', 'rsa', '-pubin', '-in', public,
                                             '-RSAPublicKey_out', '-outform', 'DER')).hexdigest()
        seen = set()
        for signature in signatures['sha256']:
            if (not isinstance(signature, dict) or set(signature) != {'pcrs', 'pkfp', 'pol', 'sig'}
                    or signature['pcrs'] != [11] or signature['pkfp'] != fingerprint
                    or signature['pol'] not in policies or signature['pol'] in seen):
                raise ValueError('PCR signature does not match measured UKI or expected signer')
            seen.add(signature['pol'])
            (directory / 'policy').write_bytes(bytes.fromhex(signature['pol']))
            signed = base64.b64decode(signature['sig'], validate=True)
            if not 256 <= len(signed) <= 512:
                raise ValueError('PCR RSA signature outside bound')
            (directory / 'signature').write_bytes(signed)
            command('openssl', 'dgst', '-sha256', '-verify', public,
                    '-signature', directory / 'signature', directory / 'policy')
    return {'slot': slot, 'pcr_approval': True, 'bank': 'sha256', 'pcrs': [11],
            'phases': list(PHASES), 'public_key_sha256': hashlib.sha256(expected_public).hexdigest(),
            'policy_digests': sorted(policies)}
