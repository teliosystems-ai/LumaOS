#!/usr/bin/env python3
"""Authenticate only the reviewed Chrony release with its fixed upstream key.

No caller-selected keys, default keyrings, network key discovery or JSON claim
can satisfy this boundary. gpgv supplies cryptographic verification; reviewed
exact key/signature/archive pins supply the static release selection policy.
This does not claim gpgv implements live key expiry/revocation discovery.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

VERSION = '4.9'
ARCHIVE_NAME = 'chrony-4.9.tar.gz'
URL = 'https://chrony-project.org/releases/' + ARCHIVE_NAME
SIGNATURE_URL = 'https://chrony-project.org/releases/chrony-4.9-tar-gz-asc.txt'
ARCHIVE_SHA256 = '4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0'
SIGNATURE_SHA256 = '380025ebf659589bedde8b1462b8ff7289289752cdd6143c8d028cc85212b327'
KEY_SHA256 = 'eabc4a3051a4ad461e38e529502b91c07607495c90917e7c988d91e4722c3dff'
FINGERPRINT = '8F375C7E8D0EE125A3D3BD51537E2B76F7680DAC'
ARCHIVE_LIMIT = 4 * 1024 * 1024
SIGNATURE_LIMIT = 16 * 1024
KEY_LIMIT = 32 * 1024
ASSETS = Path(__file__).resolve().parent
GPGV = Path('/usr/bin/gpgv')


def bounded(path, limit):
    """Pin a regular descriptor and reject named/descriptor changes during read."""
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
        raise ValueError('UTC release input must be bounded single-link regular data')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as file:
        opened = os.fstat(file.fileno())
        data = file.read(limit + 1)
        final = os.fstat(file.fileno())
    identity = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mode, m.st_uid,
                          m.st_gid, m.st_nlink, m.st_mtime_ns, m.st_ctime_ns)
    if (identity(before) != identity(opened) or identity(opened) != identity(final) or
            identity(final) != identity(path.lstat()) or len(data) != final.st_size or len(data) > limit):
        raise ValueError('UTC release input changed during its pinned observation')
    return data


def dearmor_key(key):
    lines = key.decode('ascii').splitlines()
    if (len(lines) < 5 or lines[0] != '-----BEGIN PGP PUBLIC KEY BLOCK-----' or
            lines[1] != '' or lines[-1] != '-----END PGP PUBLIC KEY BLOCK-----' or
            len(lines[-2]) != 5 or not lines[-2].startswith('=')):
        raise ValueError('fixed UTC upstream key is not canonical armored public data')
    raw = base64.b64decode(''.join(lines[2:-2]), validate=True)
    expected_crc = base64.b64decode(lines[-2][1:], validate=True)
    crc = 0xB704CE
    for byte in raw:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    if len(raw) > KEY_LIMIT or (crc & 0xFFFFFF).to_bytes(3, 'big') != expected_crc:
        raise ValueError('fixed UTC upstream key armor checksum mismatch')
    return raw


def parse_status(data, returncode):
    if returncode != 0 or len(data) > 65536:
        raise ValueError('detached UTC upstream release signature verification failed')
    lines = data.decode('ascii', errors='strict').splitlines()
    records = []
    for line in lines:
        if not line.startswith('[GNUPG:] '):
            raise ValueError('unexpected UTC verifier status channel')
        fields = line[len('[GNUPG:] '):].split()
        if not fields or fields[0] not in ('NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG'):
            raise ValueError('unapproved UTC release signature status')
        records.append(fields)
    valid = [fields for fields in records if fields[0] == 'VALIDSIG']
    good = [fields for fields in records if fields[0] == 'GOODSIG']
    if (len(valid) != 1 or len(good) != 1 or
            sum(fields[0] == 'NEWSIG' for fields in records) != 1):
        raise ValueError('UTC release requires exactly one detached signature')
    # VALIDSIG: fingerprint date timestamp expire version reserved pubkey hash
    # sigclass [primary-fingerprint]. This release is signed by the primary RSA
    # key itself; arbitrary subkeys are not admitted even under the same primary.
    fields = valid[0]
    if (len(fields) not in (10, 11) or fields[1] != FINGERPRINT or
            (len(fields) == 11 and fields[10] != FINGERPRINT) or
            fields[2] != '2026-08-27' or fields[4:10] != ['0', '4', '0', '1', '10', '00'] or
            good[0][1] != FINGERPRINT[-16:] or not fields[3].isdigit()):
        raise ValueError('UTC release signer, binary signature or strong digest differs from approved release')
    return int(fields[3])


def _authenticate(archive, signature=None, work=None):
    archive = Path(archive)
    signature = Path(signature) if signature is not None else archive.with_name(ARCHIVE_NAME + '.asc')
    archive_bytes = bounded(archive, ARCHIVE_LIMIT)
    signature_bytes = bounded(signature, SIGNATURE_LIMIT)
    key = bounded(ASSETS / 'upstream-signing-key.asc', KEY_LIMIT)
    for data, pin, label in [(archive_bytes, ARCHIVE_SHA256, 'archive'),
                             (signature_bytes, SIGNATURE_SHA256, 'signature'),
                             (key, KEY_SHA256, 'public key')]:
        if hashlib.sha256(data).hexdigest() != pin:
            raise ValueError('UTC release ' + label + ' differs from reviewed fixed pin')
    executable = GPGV.lstat()
    if (not stat.S_ISREG(executable.st_mode) or executable.st_uid != 0 or
            executable.st_mode & 0o022 or not executable.st_mode & 0o111):
        raise ValueError('UTC release requires the protected fixed gpgv executable')
    # Snapshot all verifier inputs into a new private directory on the supplied
    # build volume. Neither caller path changes nor ambient GnuPG settings can
    # alter the detached signature/key/archive bytes actually verified.
    with tempfile.TemporaryDirectory(prefix='utc-release-verification-',
                                     dir=Path(work) if work is not None else archive.parent) as directory:
        directory = Path(directory)
        directory.chmod(0o700)
        for name, data in [('archive', archive_bytes), ('signature', signature_bytes),
                           ('trusted.gpg', dearmor_key(key))]:
            with (directory / name).open('xb') as file:
                file.write(data)
            (directory / name).chmod(0o400)
        completed = subprocess.run(
            [str(GPGV), '--homedir', str(directory), '--keyring', str(directory / 'trusted.gpg'),
             '--status-fd', '1', '--', str(directory / 'signature'), str(directory / 'archive')],
            capture_output=True, timeout=15, check=False,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        created = parse_status(completed.stdout, completed.returncode)
    if (bounded(archive, ARCHIVE_LIMIT) != archive_bytes or
            bounded(signature, SIGNATURE_LIMIT) != signature_bytes or
            bounded(ASSETS / 'upstream-signing-key.asc', KEY_LIMIT) != key):
        raise ValueError('UTC release evidence changed after cryptographic verification')
    record = {'schema_version': 2, 'upstream': 'chrony', 'version': VERSION, 'url': URL,
            'sha256': ARCHIVE_SHA256, 'bytes': len(archive_bytes), 'signature_verified': True,
            'signature': {'url': SIGNATURE_URL, 'sha256': SIGNATURE_SHA256,
                          'bytes': len(signature_bytes), 'signer_fingerprint': FINGERPRINT,
                          'primary_fingerprint': FINGERPRINT, 'hash_algorithm': 'SHA512',
                          'signature_class': 'binary-document', 'created_unix': created,
                          'key_sha256': KEY_SHA256},
            'verification': 'fixed-reviewed-key-gpgv-detached-release',
            'source_review': 'fixed-provider-NTS-good-sample-hook-and-closed-seccomp-candidate',
            'qualification': 'native-image-network-clock-and-confinement-testing-required'}
    if record != json.loads(bounded(ASSETS / 'reviewed-release.json', 16384)):
        raise ValueError('actual authenticated UTC release differs from compiled reviewed identity')
    return record, archive_bytes, signature_bytes


def verify(archive, signature=None, work=None):
    return _authenticate(archive, signature, work)[0]


def _verified_provenance(archive, provenance=None, work=None):
    archive = Path(archive)
    provenance = Path(provenance) if provenance is not None else archive.with_name('chrony-4.9.provenance.json')
    captured = _authenticate(archive, work=work)
    current = captured[0]
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('duplicate UTC provenance field')
            result[name] = value
        return result
    supplied = json.loads(bounded(provenance, 16 * 1024), object_pairs_hook=unique)
    if (json.dumps(supplied, sort_keys=True, separators=(',', ':')) !=
            json.dumps(current, sort_keys=True, separators=(',', ':'))):
        raise ValueError('UTC release provenance is absent, unverified or differs from actual signature verification')
    return captured


def verified_provenance(archive, provenance=None, work=None):
    return _verified_provenance(archive, provenance, work)[0]


def snapshot(archive, output, signature=None, provenance=None, work=None):
    """Publish only bytes retained by the actual completed crypto observation.

    Partial publication is preserved; destinations must be new. A subsequent
    source-caller rename/write cannot change this private build-owned snapshot.
    """
    captured = (_verified_provenance(archive, provenance, work) if provenance is not None else
                _authenticate(archive, signature, work))
    record, archive_bytes, signature_bytes = captured
    output = Path(output)
    if output.exists() or output.is_symlink() or output.name in ('', '.', '..'):
        raise ValueError('authenticated UTC snapshot destination must be new')
    parent_path = output.parent.resolve(strict=True)
    if output.parent.is_symlink():
        raise ValueError('authenticated UTC snapshot parent cannot be a symlink')
    output = parent_path / output.name
    parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid)
    before = identity(os.fstat(parent))
    try:
        if before != identity(parent_path.lstat()):
            raise ValueError('authenticated UTC snapshot parent changed')
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        directory = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
        try:
            directory_identity = identity(os.fstat(directory))
            if (directory_identity[3] != os.geteuid() or directory_identity[2] & 0o777 != 0o700):
                raise ValueError('authenticated UTC snapshot directory must be private and build-owned')
            files = {ARCHIVE_NAME: archive_bytes, ARCHIVE_NAME + '.asc': signature_bytes,
                     'chrony-4.9.provenance.json': (json.dumps(record, sort_keys=True) + '\n').encode()}
            for name, data in files.items():
                descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o400, dir_fd=directory)
                with os.fdopen(descriptor, 'w+b') as file:
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())
                    file.seek(0)
                    actual = file.read(len(data) + 1)
                    retained = os.fstat(file.fileno())
                    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (actual != data or hashlib.sha256(actual).digest() != hashlib.sha256(data).digest() or
                            identity(retained) != identity(named) or retained.st_nlink != 1 or
                            retained.st_size != len(data) or retained.st_mode & 0o777 != 0o400):
                        raise ValueError('authenticated UTC snapshot file changed during publication')
            os.fsync(directory)
            if (before != identity(os.fstat(parent)) or before != identity(parent_path.lstat()) or
                    directory_identity != identity(os.fstat(directory)) or
                    directory_identity != identity(os.stat(output.name, dir_fd=parent, follow_symlinks=False)) or
                    directory_identity != identity(output.lstat())):
                raise ValueError('authenticated UTC snapshot namespace changed during publication')
        finally:
            os.close(directory)
        os.fsync(parent)
    finally:
        os.close(parent)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path)
    args = parser.parse_args()
    if args.snapshot is None:
        print(json.dumps(verified_provenance(args.archive, work=args.work), sort_keys=True))
    else:
        snapshot(args.archive, args.snapshot,
                 provenance=args.archive.with_name('chrony-4.9.provenance.json'), work=args.work)
        print(str(args.snapshot))
