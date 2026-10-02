#!/usr/bin/env python3
"""Exercise native sealed-child TPM policy using only a disposable software TPM."""
import os
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('isolated root container without host TPM/socket required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='luma-tpm-native-') as folder:
        root = Path(folder)
        (root / 'state').mkdir()
        transport = f'swtpm:path={root}/tpm.sock'
        env = dict(os.environ, TSS2_LOG='all+NONE', LUMA_TPM_TEST_DIRECTORY=str(root))
        owner = os.urandom(32)
        (root / 'owner.binary').write_bytes(owner)
        (root / 'owner.tools').write_text('hex:' + owner.hex(), encoding='ascii')

        def command(*args, okay=True):
            result = subprocess.run([str(arg) for arg in args], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    timeout=300)
            if okay and result.returncode:
                raise RuntimeError(f'{args[0]} failed ({result.returncode}): '
                                   + result.stderr.decode('utf-8', 'replace')[:1200])
            return result.returncode == 0

        def start():
            process = subprocess.Popen([
                'swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state,mode=0600',
                '--server', f'type=unixio,path={root}/tpm.sock',
                '--ctrl', f'type=unixio,path={root}/tpm.sock.ctrl',
                '--flags', 'not-need-init,startup-clear'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 10
            while not (root / 'tpm.sock.ctrl').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('fixture TPM did not start')
                time.sleep(.02)
            return process

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

        def run_case(test, mode=None):
            environment = dict(env)
            if mode:
                environment['LUMA_TPM_TEST_NATIVE_MODE'] = mode
            print('NATIVE_TPM_CASE=' + (mode or test), flush=True)
            subprocess.run(['cargo', 'test', '--offline', '--locked',
                            test, '--', '--ignored', '--exact', '--nocapture'],
                           env=environment, check=True, timeout=300)

        def sign_current():
            command('tpm2_startauthsession', '-T', transport, '-S', root / 'session')
            try:
                command('tpm2_policypcr', '-T', transport, '-S', root / 'session',
                        '-l', 'sha256:11', '-L', root / 'signed.policy')
            finally:
                command('tpm2_flushcontext', '-T', transport, root / 'session')
            command('openssl', 'dgst', '-sha256', '-sign', root / 'private.pem',
                    '-out', root / 'signature', root / 'signed.policy')
            signature_json()

        def signature_json():
            (root / 'pcr-signature.json').write_text(json.dumps({'sha256': [{
                'pcrs': [11],
                'pkfp': hashlib.sha256((root / 'public.der').read_bytes()).hexdigest(),
                'pol': (root / 'signed.policy').read_bytes().hex(),
                'sig': base64.b64encode((root / 'signature').read_bytes()).decode('ascii'),
            }]}), encoding='ascii')

        def no_transients():
            result = subprocess.run(['tpm2_getcap', '-T', transport, 'handles-transient'],
                                    env=env, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=30)
            lines = result.stdout.decode('ascii').splitlines()
            if any(not re.fullmatch(r'- 0x[0-9a-fA-F]{8}', line) for line in lines) or lines:
                raise RuntimeError('native credential operation leaked transient TPM handles')

        emulator = start()
        try:
            command('tpm2_changeauth', '-T', transport, '-c', 'o',
                    f'file:{root}/owner.tools')
            run_case('tpm::tests::emulator_existing_owner_parent_provisioning')
            no_transients()
            command('openssl', 'genpkey', '-algorithm', 'RSA',
                    '-pkeyopt', 'rsa_keygen_bits:2048', '-out', root / 'private.pem')
            command('openssl', 'rsa', '-in', root / 'private.pem', '-pubout',
                    '-out', root / 'pcr-public.pem')
            command('openssl', 'rsa', '-in', root / 'private.pem',
                    '-RSAPublicKey_out', '-outform', 'DER', '-out', root / 'public.der')
            sign_current()
            run_case('tpm::tests::emulator_native_sealed_child', 'seal')
            run_case('owner_credential::tests::emulator_native_envelope', 'seal')
            for mode in ('allow', 'wrong-name', 'tamper'):
                run_case('tpm::tests::emulator_native_sealed_child', mode)
                run_case('owner_credential::tests::emulator_native_envelope', mode)
            no_transients()
            signed = (root / 'signature').read_bytes()
            (root / 'signature').write_bytes(bytes([signed[0] ^ 1]) + signed[1:])
            signature_json()
            run_case('tpm::tests::emulator_native_sealed_child', 'deny')
            run_case('owner_credential::tests::emulator_native_envelope', 'deny')
            (root / 'signature').write_bytes(signed)
            signature_json()
            command('tpm2_pcrextend', '-T', transport, '11:sha256=' + '55' * 32)
            run_case('tpm::tests::emulator_native_sealed_child', 'deny')
            run_case('owner_credential::tests::emulator_native_envelope', 'deny')
            sign_current()
            run_case('tpm::tests::emulator_native_sealed_child', 'allow')
            run_case('owner_credential::tests::emulator_native_envelope', 'allow')
            command('tpm2_pcrextend', '-T', transport, '7:sha256=' + '66' * 32)
            run_case('tpm::tests::emulator_native_sealed_child', 'deny')
            run_case('owner_credential::tests::emulator_native_envelope', 'deny')
            no_transients()
            command('tpm2_shutdown', '-T', transport, '-c')
            stop(emulator)
            emulator = start()
            command('tpm2_readpublic', '-T', transport, '-c', '0x81004c41',
                    '-n', root / 'parent-after.name')
            if (root / 'parent.name').read_bytes() != (root / 'parent-after.name').read_bytes():
                raise RuntimeError('parent Name changed after restart')
            sign_current()
            run_case('tpm::tests::emulator_native_sealed_child', 'allow')
            run_case('owner_credential::tests::emulator_native_envelope', 'allow')
            no_transients()
            print('NATIVE_OWNER_SEALED_CHILD_SOFTWARE_TPM_PASSED', flush=True)
        finally:
            stop(emulator)


if __name__ == '__main__':
    main()
