#!/usr/bin/env python3
"""Run fixed upstream NTS/auth/crypto units from freshly authenticated source.

Mandatory isolated build lane: network disabled, all capabilities dropped, no
host mounts beyond readonly source/cache and a new bounded D work directory.
No daemon, kernel tests, host configuration or host-clock operations are run.
Upstream TST_Skip returns zero; exact PASS validation deliberately rejects that.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

import prepare_chrony
import verify_release

UNITS = ('hash', 'cmac', 'siv', 'ntp_ext', 'ntp_auth', 'nts_ntp_auth',
         'nts_ntp_client', 'nts_ke_session')
SEEDS = (1, 2)


def command(argv, cwd, transcript, timeout):
    result = subprocess.run(argv, cwd=cwd, timeout=timeout, capture_output=True, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': '1787839200',
                                 'CFLAGS': '-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE',
                                 'LDFLAGS': '-Wl,-z,relro,-z,now -pie'})
    with transcript.open('ab') as file:
        file.write(('COMMAND ' + ' '.join(argv) + '\n').encode())
        file.write(result.stdout)
        file.write(result.stderr)
        file.write(('EXIT ' + str(result.returncode) + '\n').encode())
        file.flush()
        os.fsync(file.fileno())
    if result.returncode != 0:
        raise ValueError('authenticated upstream unit/build command failed: ' + argv[0])
    if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 4 * 1024 * 1024:
        raise ValueError('authenticated upstream unit/build output exceeds its bound')
    return result.stdout.decode('utf-8', errors='strict')


def run(archive, output):
    archive = Path(archive)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('upstream unit evidence destination must be new')
    parent = output.parent.resolve(strict=True)
    if not parent.is_dir() or output.parent.is_symlink():
        raise ValueError('upstream unit evidence requires its dedicated build directory')
    output = parent / output.name
    if not Path('/.dockerenv').is_file():
        raise ValueError('upstream unit lane requires an isolated build container')
    status = Path('/proc/self/status').read_text()
    for field in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        values = re.findall(r'^' + field + r':\s*([0-9a-f]+)$', status, re.MULTILINE)
        if len(values) != 1 or int(values[0], 16) != 0:
            raise ValueError('upstream unit lane must drop all kernel capabilities')
    interfaces = {path.name for path in Path('/sys/class/net').iterdir()}
    if interfaces != {'lo'}:
        raise ValueError('upstream unit lane must have network none')
    output.mkdir(mode=0o700)
    captured = verify_release.snapshot(archive, output / 'authenticated',
                                      signature=verify_release.ASSETS / 'chrony-4.9.tar.gz.asc', work=output)
    archive = captured / verify_release.ARCHIVE_NAME
    actual = verify_release.verified_provenance(archive, work=output)
    transcript = output / 'transcript.txt'
    transcript.touch(mode=0o600, exist_ok=False)
    raw = output / 'upstream'
    raw.mkdir(mode=0o700)
    # The exact archive already passed real detached-signature verification.
    # Validate the extraction namespace/size as defense in depth before writes.
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        if len(members) > 4096 or sum(member.size for member in members) > 32 * 1024 * 1024:
            raise ValueError('authenticated source extraction exceeds its bound')
        for member in members:
            path = Path(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or
                    path.parts[0] != 'chrony-4.9' or not (member.isfile() or member.isdir())):
                raise ValueError('authenticated source extraction has an unsafe member')
        source.extractall(raw, members=members, filter='data')
    patched = output / 'patched'
    prepare_chrony.prepare(raw / 'chrony-4.9', patched, release=True)
    started = time.monotonic()
    command(['./configure', '--disable-readline', '--without-editline', '--enable-scfilter',
             '--with-user=luma-utc-producer', '--sysconfdir=/usr/share/luma-os/utc',
             '--localstatedir=/run'], patched, transcript, 60)
    config = (patched / 'config.h').read_text()
    for feature in ('NTS', 'PRIVDROP', 'SCFILTER'):
        if '#define FEAT_' + feature + ' 1\n' not in config:
            raise ValueError('upstream unit lane lacks production-required feature: ' + feature)
    command(['make', '-j1', 'chronyd'], patched, transcript, 300)
    units = patched / 'test/unit'
    command(['make', '-j1', *(unit + '.test' for unit in UNITS)], units, transcript, 180)
    results = []
    for name in UNITS:
        for seed in SEEDS:
            stdout = command(['./' + name + '.test', '-s', str(seed)], units, transcript, 30)
            if re.fullmatch(r'Testing ' + re.escape(name) + r'\s+PASS\n', stdout) is None:
                raise ValueError('upstream unit failed or skipped instead of exact PASS: ' + name)
            results.append({'unit': name, 'seed': seed, 'result': 'PASS'})
    evidence = {'schema_version': 1, 'release': actual,
                'source_inputs': json.loads((patched / 'luma-hook-inputs.json').read_bytes()),
                'elapsed_seconds': time.monotonic() - started, 'results': results,
                'transcript_sha256': hashlib.sha256(transcript.read_bytes()).hexdigest(),
                'qualification': 'isolated-upstream-crypto-auth-units-not-native-NTS-clock-confinement'}
    with (output / 'evidence.json').open('x', encoding='utf-8', newline='\n') as file:
        json.dump(evidence, file, indent=2, sort_keys=True)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(evidence, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.archive, args.output)
