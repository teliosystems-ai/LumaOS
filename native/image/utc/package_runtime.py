#!/usr/bin/env python3
"""Bind exact installed producer code, read-only controls and resolved ELF closure.

Run inside the native image assembly root after installing the checked release
candidate and profiles. The output is image inventory, not a signature or proof
of live NTS qualification. Never run a time daemon during packaging.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess

REQUIRED = {
    'executable': '/usr/libexec/luma-os/chronyd',
    'configuration': '/usr/share/luma-os/utc/chrony.conf',
    'certificates': '/usr/share/luma-os/utc/ca-certificates.crt',
    'policy': '/usr/share/luma-os/utc/approved-policy.json',
    'service': '/usr/lib/systemd/system/luma-utc-producer.service',
    'confinement': '/etc/apparmor.d/luma-utc-producer',
    'provenance': '/usr/share/luma-os/utc/upstream-provenance.json',
    'source_inputs': '/usr/share/luma-os/utc/source-inputs.json',
    'recovery_service': '/usr/lib/systemd/system/luma-utc-recovery-producer.service',
    'recovery_confinement': '/etc/apparmor.d/luma-utc-recovery-producer',
}


def inventory(root):
    root = root.resolve(strict=True)
    assets = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('luma_packaged_release_verifier', assets / 'verify_release.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    source = root / 'usr/share/luma-os/utc/source/chrony-4.9.tar.gz'
    # Reverify bytes, not the caller's signature_verified field, before ldd or
    # publication. Runtime retains both records as mandatory immutable pins.
    verifier.verified_provenance(source, root / REQUIRED['provenance'].lstrip('/'), work=root)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate UTC source input field')
            value[key] = item
        return value
    actual = json.loads(verifier.bounded(root / REQUIRED['source_inputs'].lstrip('/'), 32768),
                        object_pairs_hook=unique)
    reviewed = json.loads(verifier.bounded(assets / 'reviewed-source-inputs.json', 32768))
    if (json.dumps(actual, sort_keys=True, separators=(',', ':')) !=
            json.dumps(reviewed, sort_keys=True, separators=(',', ':'))):
        raise ValueError('UTC packaged hook/source inputs differ from reviewed identity')
    files = []
    paths = set()
    for role, path in REQUIRED.items():
        paths.add((role, path))
    # ldd is not executed on caller bytes: the builder has already installed
    # the verified locally built chronyd at this one fixed immutable image path.
    # Resolve loader symlinks into actual canonical /usr ELF objects, matching
    # /proc/maps, and retain the complete dependency closure in the manifest.
    result = subprocess.run(['chroot', str(root), '/usr/bin/ldd', REQUIRED['executable']],
                            check=True, capture_output=True, text=True, timeout=10,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if 'not found' in result.stdout or result.stderr:
        raise ValueError('release ELF dependency closure is incomplete')
    for line in result.stdout.splitlines():
        match = re.search(r'(?:=>\s+)?(/[^\s]+)\s+\(0x[0-9a-f]+\)', line)
        if not match:
            if not re.fullmatch(r'\s*linux-vdso\.so\.1\s+\(0x[0-9a-f]+\)', line):
                raise ValueError('unrecognized loader dependency report')
            continue
        image_path = match.group(1)
        resolved = subprocess.run(['chroot', str(root), '/usr/bin/realpath', '-e', image_path],
                                  check=True, capture_output=True, text=True, timeout=5,
                                  env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}).stdout.strip()
        if not resolved.startswith('/usr/lib/x86_64-linux-gnu/') or '.so' not in Path(resolved).name:
            raise ValueError('release library does not use the fixed canonical namespace')
        paths.add(('library', resolved))
    for role, path in sorted(paths, key=lambda item: item[1]):
        physical = root / path.lstrip('/')
        m = physical.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1 or m.st_mode & 0o7022:
            raise ValueError('release artifact is not protected regular root-owned data: ' + path)
        data = physical.read_bytes()
        if not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError('release artifact exceeds its bounded size')
        files.append({'role': role, 'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    if not len(REQUIRED) + 1 <= len(files) <= 64 or sum(f['bytes'] for f in files) > 256 * 1024 * 1024:
        raise ValueError('release closure exceeds its bounded inventory')
    policy = (root / REQUIRED['policy'].lstrip('/')).read_bytes()
    policy_digest = hashlib.sha256(b'luma-native-approved-utc-policy-v1\0' + policy).hexdigest()
    output = root / 'usr/share/luma-os/utc/runtime.json'
    value = {'schema_version': 1, 'policy_sha256': policy_digest, 'files': files}
    with output.open('xb') as file:
        file.write(json.dumps(value, separators=(',', ':')).encode())
        file.flush()
        os.fsync(file.fileno())
    output.chmod(0o644)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    inventory(parser.parse_args().root)
