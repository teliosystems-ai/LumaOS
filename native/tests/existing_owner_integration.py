#!/usr/bin/env python3
"""Provision one native NV index under pre-existing fixture ownership only."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('fresh disposable container without host TPM/socket required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='luma-tpm-existing-owner-') as folder:
        work = Path(folder)
        (work / 'state').mkdir()
        owner = os.urandom(32)
        (work / 'owner.binary').write_bytes(owner)
        (work / 'owner.tools').write_text('hex:' + owner.hex(), encoding='ascii')
        transport = f'swtpm:path={work}/tpm.sock'
        env = dict(os.environ, TSS2_LOG='all+NONE', LUMA_TPM_TEST_DIRECTORY=str(work))
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
                    raise RuntimeError('fixture TPM failed to start')
                time.sleep(.02)
            # TEST SETUP ONLY: establish existing ownership before native code.
            # No product entrypoint exposes HierarchyChangeAuth or TPM clear.
            subprocess.run(['tpm2_changeauth', '-T', transport, '-c', 'o', f'file:{work}/owner.tools'],
                           env=env, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['cargo', 'test', '--offline', '--locked',
                            'tpm::tests::emulator_existing_owner_parent_provisioning',
                            '--', '--ignored', '--exact', '--nocapture'],
                           env=env, check=True, timeout=300)
            subprocess.run(['tpm2_readpublic', '-T', transport, '-c', '0x81004c41',
                            '-n', str(work / 'parent.readback')],
                           env=env, check=True, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if (work / 'parent.name').read_bytes() != (work / 'parent.readback').read_bytes():
                raise RuntimeError('persistent parent TPM Name differs from native readback')
            subprocess.run(['cargo', 'test', '--offline', '--locked',
                            'tpm::tests::emulator_existing_owner_provisioning',
                            '--', '--ignored', '--exact', '--nocapture'],
                           env=env, check=True, timeout=300)
            def handles():
                result = subprocess.run(['tpm2_getcap', '-T', transport, 'handles-transient'],
                    env=env, check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                lines = result.stdout.decode('ascii').splitlines()
                if any(not re.fullmatch(r'- 0x[0-9a-fA-F]{8}', line) for line in lines):
                    raise RuntimeError('unexpected transient handle inventory')
                return [line[2:] for line in lines]
            if handles():
                raise RuntimeError('native provisioning leaked transient objects')
            # Existing custodian authorization remains valid after provisioning.
            subprocess.run(['tpm2_createprimary', '-T', transport, '-C', 'o',
                            '-P', f'file:{work}/owner.tools', '-c', str(work / 'owner-primary')],
                           env=env, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            created = handles()
            if len(created) != 1:
                raise RuntimeError('verification must own exactly one transient object')
            # Tools createprimary saved an ESYS object reference, not the
            # session context format expected by flushcontext's file argument.
            # Flush only the exact handle added by this fixture, never all.
            subprocess.run(['tpm2_flushcontext', '-T', transport, created[0]],
                           env=env, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if handles():
                raise RuntimeError('verification object was not released')
            print('EXISTING_OWNER_PROVISIONING_PASSED', flush=True)
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
