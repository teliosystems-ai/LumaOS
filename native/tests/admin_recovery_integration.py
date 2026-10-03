#!/usr/bin/env python3
"""Targeted inert-journal recovery check; disposable software TPM only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0',
                                              '/var/run/docker.sock'))):
        raise SystemExit('fresh root tools container without host TPM/socket required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='luma-tpm-recovery-') as folder:
        work = Path(folder)
        (work / 'state').mkdir()
        secret = os.urandom(32)
        (work / 'auth').write_bytes(secret)
        (work / 'tools-auth').write_text('hex:' + secret.hex(), encoding='ascii')
        domain = 'ab' * 32
        (work / 'genesis').write_bytes(hashlib.sha256(
            b'luma-native-admin-genesis-v1\0' + bytes.fromhex(domain)).digest())
        (work / 'journal.json').write_text(json.dumps({
            'schema_version': 1, 'deployment': domain, 'entries': []},
            separators=(',', ':')), encoding='utf-8')
        transport = f'swtpm:path={work}/tpm.sock'
        environment = dict(os.environ, TSS2_LOG='all+NONE',
                           LUMA_TPM_TEST_DIRECTORY=str(work))
        emulator = subprocess.Popen([
            'swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={work}/state,mode=0600',
            '--server', f'type=unixio,path={work}/tpm.sock',
            '--ctrl', f'type=unixio,path={work}/tpm.sock.ctrl',
            '--flags', 'not-need-init,startup-clear'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not (work / 'tpm.sock.ctrl').exists():
                if emulator.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('isolated software TPM failed to start')
                time.sleep(.02)
            # Fixture provisioning only. The product recovery API cannot
            # define, extend, clear or reset an index.
            for command in [
                ['tpm2_nvdefine', '-T', transport, '-C', 'o', '-g', 'sha256',
                 '-s', '32', '-a', '0x02040044', '-p', f'file:{work}/tools-auth', '0x01804c41'],
                ['tpm2_nvextend', '-T', transport, '-C', '0x01804c41',
                 '-P', f'file:{work}/tools-auth', '-i', work / 'genesis', '0x01804c41'],
            ]:
                subprocess.run(command, env=environment, check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([
                'cargo', 'test', '--offline', '--locked',
                'tpm::tests::emulator_committed_journal_recovery',
                '--', '--ignored', '--exact', '--nocapture'],
                env=environment, check=True, timeout=300)
            print('ADMIN_COMMITTED_RECOVERY_SOFTWARE_TPM_PASSED', flush=True)
        finally:
            if emulator.poll() is None:
                emulator.terminate()
                try:
                    emulator.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    emulator.kill()
                    emulator.wait(timeout=10)


if __name__ == '__main__':
    main()
