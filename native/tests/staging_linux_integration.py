#!/usr/bin/env python3
"""Real Linux mount/storage/CLI boundaries in a disposable tools container only.

Needs CAP_SYS_ADMIN for private container mounts; no host devices or network.
Never run on the installed product or give this container host PID/mount namespaces.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def run(*args, expected=0):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=60)
    if result.returncode != expected:
        raise RuntimeError(f'{args[0]}: wanted {expected}, got {result.returncode}: '
                           f'{result.stdout[-2048:]!r} {result.stderr[-2048:]!r}')
    return result.stdout, result.stderr


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


@contextmanager
def mounted(*args, target):
    run('mount', *args, target)
    try:
        yield
    finally:
        run('umount', target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('requires a fresh disposable root tools container')
    if args.output.exists():
        raise SystemExit('evidence output must be fresh')
    state = Path('/var/lib/luma-os')
    trust = Path('/usr/share/luma-os')
    if state.exists() or trust.exists():
        raise SystemExit('refusing existing platform state/trust; use a fresh tools container')
    binary = args.binary.resolve(strict=True)
    state.mkdir(mode=0o700)
    trust.mkdir(mode=0o700)
    base = state / 'staging'
    namespace = base / 'verified-v1'
    passed = []

    def clean(expected=0):
        return run(binary, 'staging-clean', expected=expected)

    clean()
    with tempfile.TemporaryDirectory(prefix='luma-staging-integration-') as folder:
        work = Path(folder)
        outside = work / 'sentinel'
        outside.mkdir(mode=0o700)
        sentinel = outside / 'root.ext4'
        sentinel.write_bytes(b'not a cleanup target')
        sentinel.chmod(0o600)
        snapshot = namespace / ('bundle-' + 'a' * 32)
        snapshot.mkdir(mode=0o700)
        with mounted('--bind', outside, target=snapshot):
            if snapshot.stat().st_dev != namespace.stat().st_dev:
                raise RuntimeError('fixture must specifically test a same-filesystem bind mount')
            _, error = clean(expected=1)
            if b'unsafe snapshot directory' not in error:
                raise RuntimeError('wrong bind-mount refusal')
            if sentinel.read_bytes() != b'not a cleanup target':
                raise RuntimeError('cleanup touched bind target')
        clean()
        passed.append('same-filesystem-directory-bind-refused')

        snapshot.mkdir(mode=0o700)
        member = snapshot / 'root.ext4'
        member.touch(mode=0o600)
        with mounted('--bind', sentinel, target=member):
            _, error = clean(expected=1)
            if b'unsafe snapshot member' not in error:
                raise RuntimeError('wrong file-bind refusal')
            if sentinel.read_bytes() != b'not a cleanup target':
                raise RuntimeError('cleanup touched bound file')
        clean()
        passed.append('same-filesystem-file-bind-refused')

        # Legacy snapshots and recovery mount workspaces use a different namespace.
        legacy = base / ('bundle-' + 'b' * 32)
        legacy.mkdir(mode=0o700)
        (legacy / 'root.ext4').write_bytes(b'legacy preserved')
        recovery = base / 'recovery-do-not-touch'
        recovery.mkdir(mode=0o700)
        clean()
        if (legacy / 'root.ext4').read_bytes() != b'legacy preserved' or not recovery.is_dir():
            raise RuntimeError('cleanup crossed namespace boundary')
        passed.append('legacy-and-recovery-workspaces-preserved')

        # Authentic lab signature and real sparse payload. Only the disposable
        # container receives these fresh test keys; private material is not exported.
        source = work / 'bundle'
        source.mkdir()
        names = ('root.ext4', 'root.verity', 'slot-a.efi', 'slot-b.efi',
                 'bootloader.efi', 'secureboot.cer')
        artifacts = []
        for name in names:
            path = source / name
            with path.open('xb') as stream:
                stream.truncate(512 * 1024**2 if name == 'root.ext4' else 4096)
            artifacts.append({'name': name, 'bytes': path.stat().st_size, 'sha256': digest(path)})
        manifest = {'schema_version': 1, 'release': 'storage-test', 'sequence': 1,
                    'environment': 'lab', 'architecture': 'amd64', 'ubuntu': '24.04',
                    'edition': 'headless', 'root_hash': 'a' * 64,
                    'root_bytes': 512 * 1024**2, 'hash_bytes': 4096, 'artifacts': artifacts}
        (source / 'release.json').write_text(json.dumps(manifest), encoding='utf-8')
        key = work / 'test-only-private.pem'
        run('openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', key)
        key.chmod(0o600)
        run('openssl', 'pkey', '-in', key, '-pubout', '-out', trust / 'release.pub')
        run('openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin',
            '-in', source / 'release.json', '-out', source / 'release.sig')
        output, _ = run(binary, 'verify', source)
        if json.loads(output) != manifest or list(namespace.iterdir()) != [namespace / 'lock']:
            raise RuntimeError('verified snapshot was not reclaimed')
        passed.append('real-signed-bundle-verification-and-cleanup')

        signature = (source / 'release.sig').read_bytes()
        (source / 'release.sig').write_bytes(bytes(64))
        _, error = run(binary, 'verify', source, expected=1)
        if b'signature verification failed' not in error or len(list(namespace.iterdir())) != 1:
            raise RuntimeError('failed verification leaked snapshot')
        (source / 'release.sig').write_bytes(signature)
        passed.append('bad-signature-refusal-cleans-snapshot')

        (source / 'root.ext4').unlink()
        os.mkfifo(source / 'root.ext4', mode=0o600)
        _, error = run(binary, 'verify', source, expected=1)
        if b'regular file' not in error:
            raise RuntimeError('FIFO source was not refused before blocking')
        (source / 'root.ext4').unlink()
        passed.append('fifo-source-refused-without-blocking')
        with (source / 'root.ext4').open('xb') as stream:
            stream.truncate(manifest['root_bytes'])

        # Real constrained filesystem, not an injected free-space observation.
        with mounted('-t', 'tmpfs', '-o', 'size=16M,mode=0700', 'tmpfs', target=namespace):
            _, error = run(binary, 'verify', source, expected=1)
            if b'insufficient snapshot storage; no payload copied' not in error:
                raise RuntimeError('storage pressure not refused before payload access')
            if list(namespace.iterdir()) != [namespace / 'lock']:
                raise RuntimeError('pressure refusal leaked snapshot')
        passed.append('real-tmpfs-capacity-refusal-before-snapshot-copy')

        # Sparse bytes must fit by actual copy allocation, not logical length.
        with mounted('-t', 'tmpfs', '-o', 'size=96M,mode=0700', 'tmpfs', target=namespace):
            output, _ = run(binary, 'verify', source)
            if json.loads(output) != manifest or list(namespace.iterdir()) != [namespace / 'lock']:
                raise RuntimeError('sparse bundle did not fit small live-media staging')
        passed.append('sparse-logical-payload-larger-than-tmpfs-verifies')

        # Change the payload to actual nonzero bytes and resign its digest.
        # Concurrent allocation consumes space only after the real copy starts,
        # so this exercises ENOSPC cleanup, not just the admission calculation.
        root = source / 'root.ext4'
        with root.open('wb') as stream:
            for _ in range(512):
                stream.write(b'X' * 1024**2)
        manifest['artifacts'][0]['sha256'] = digest(root)
        (source / 'release.json').write_text(json.dumps(manifest), encoding='utf-8')
        run('openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin',
            '-in', source / 'release.json', '-out', source / 'release.sig')
        with mounted('-t', 'tmpfs', '-o', 'size=640M,mode=0700', 'tmpfs', target=namespace):
            copy = subprocess.Popen([str(binary), 'verify', str(source)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 30
                while not list(namespace.glob('bundle-*/root.ext4')):
                    if copy.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('never observed snapshot copy; no injected-fault claim')
                    time.sleep(.005)
                pressure = namespace / 'test-only-competing-allocation'
                with pressure.open('xb') as stream:
                    os.posix_fallocate(stream.fileno(), 0, 200 * 1024**2)
                    os.fsync(stream.fileno())
                _, error = copy.communicate(timeout=60)
                if copy.returncode != 1 or b'No space left on device' not in error:
                    raise RuntimeError(f'no actual ENOSPC failure observed: {error!r}')
                if list(namespace.glob('bundle-*')):
                    raise RuntimeError('mid-copy ENOSPC leaked snapshot')
                pressure.unlink()
                output, _ = run(binary, 'verify', source)
                if json.loads(output) != manifest or list(namespace.iterdir()) != [namespace / 'lock']:
                    raise RuntimeError('retry after pressure did not verify and reclaim')
            finally:
                if copy.poll() is None:
                    copy.kill()
                copy.wait(timeout=10)
        passed.append('real-mid-copy-enospc-cleanup-and-successful-retry')

    record = {'schema_version': 1, 'result': 'passed', 'cases': passed,
              'binary_sha256': digest(binary), 'runner_sha256': digest(Path(__file__)),
              'kernel': platform.release(), 'environment': 'disposable-linux-container',
              'physical_power_loss_tested': False, 'image_tested': False, 'gate_closing': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
