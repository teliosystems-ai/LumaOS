#!/usr/bin/env python3
"""Fixed-input sealed delivery on a disposable software TPM; no real devices."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('fresh tools container without host TPM/socket required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='luma-tpm-delivery-') as folder:
        work = Path(folder)
        (work / 'state').mkdir()
        env = dict(os.environ, TSS2_LOG='all+NONE', LUMA_TPM_TEST_DIRECTORY=str(work))
        transport = f'swtpm:path={work}/tpm.sock'

        def command(args):
            subprocess.run([str(a) for a in args], env=env, check=True, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def approve():
            command(['tpm2_startauthsession', '-T', transport, '-S', work / 'session'])
            try:
                command(['tpm2_policypcr', '-T', transport, '-S', work / 'session',
                         '-l', 'sha256:11', '-L', work / 'policy'])
            finally:
                command(['tpm2_flushcontext', '-T', transport, work / 'session'])
            command(['openssl', 'dgst', '-sha256', '-sign', work / 'private.pem',
                     '-out', work / 'signature', work / 'policy'])
            (work / 'pcr-signature.json').write_text(json.dumps({'sha256': [{
                'pcrs': [11], 'pkfp': hashlib.sha256((work / 'public.der').read_bytes()).hexdigest(),
                'pol': (work / 'policy').read_bytes().hex(),
                'sig': base64.b64encode((work / 'signature').read_bytes()).decode('ascii'),
            }]}), encoding='ascii')

        def check(mode):
            print('SEALED_DELIVERY_MODE=' + mode, flush=True)
            subprocess.run(['cargo', 'test', '--offline', '--locked',
                            'admin_credentials::tests::emulator_sealed_delivery',
                            '--', '--ignored', '--exact', '--nocapture'],
                           env=dict(env, LUMA_TPM_TEST_DELIVERY=mode), check=True, timeout=300)

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
                    raise RuntimeError('isolated TPM failed to start')
                time.sleep(.02)
            command(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                     '-out', work / 'private.pem'])
            command(['openssl', 'rsa', '-in', work / 'private.pem', '-pubout', '-out', work / 'pcr-public.pem'])
            command(['openssl', 'rsa', '-in', work / 'private.pem', '-RSAPublicKey_out',
                     '-outform', 'DER', '-out', work / 'public.der'])
            approve()
            check('seal')
            check('allow')
            command(['tpm2_pcrextend', '-T', transport, '11:sha256=' + '55' * 32])
            check('deny')
            approve()
            check('allow')  # same sealed blob; new signed PCR11 policy
            signature = (work / 'pcr-signature.json').read_bytes()
            (work / 'pcr-signature.json').write_bytes(b'{}')
            check('deny')
            (work / 'pcr-signature.json').write_bytes(signature)
            check('allow')
            command(['tpm2_pcrextend', '-T', transport, '7:sha256=' + '66' * 32])
            check('deny')  # signed PCR11 does not waive fixed PCR7
            print('SEALED_DELIVERY_SOFTWARE_TPM_PASSED', flush=True)
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
