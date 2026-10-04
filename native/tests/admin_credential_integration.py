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


def main(enrollment=False):
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
            if enrollment:
                check('seal')  # control: this helper and boot policy work with empty owner auth
                # Existing ownership is initialized ONLY inside this disposable
                # software TPM. Product enrollment never changes hierarchy auth.
                owner = os.urandom(32)
                (work / 'owner.binary').write_bytes(owner)
                (work / 'owner.hex').write_text('hex:' + owner.hex(), encoding='ascii')
                command(['tpm2_changeauth', '-T', transport, '-c', 'o',
                         f'file:{work / "owner.hex"}'])
                if isinstance(enrollment, str) and enrollment.startswith('pending-'):
                    mode = enrollment.removeprefix('pending-')
                    if mode.startswith('lost-'):
                        command(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                                 Path(__file__).parent / 'fixtures/enrollment_publication_faults.c',
                                 '-o', '/tmp/luma-enrollment-publication-faults.so', '-ldl'])
                    subprocess.run(['cargo', 'test', '--offline', '--locked',
                                    'admin_enrollment::tests::emulator_pending_enrollment_publication',
                                    '--', '--ignored', '--exact', '--nocapture'],
                                   env=dict(env, LUMA_TPM_TEST_PENDING=mode),
                                   check=True, timeout=300)
                    print('PENDING_ENROLLMENT_MODE_PASSED=' + mode, flush=True)
                    return
                if enrollment == 'resume':
                    subprocess.run(['cargo', 'test', '--offline', '--locked',
                                    'admin_enrollment::tests::emulator_resume_bound_parent_without_reallocation',
                                    '--', '--ignored', '--exact', '--nocapture'],
                                   env=env, check=True, timeout=300)
                    print('REVIEWED_BOUND_PARENT_CONTINUATION_SOFTWARE_TPM_PASSED', flush=True)
                    return
                subprocess.run(['cargo', 'test', '--offline', '--locked',
                                'admin_enrollment::tests::emulator_existing_owner_seal_refusal',
                                '--', '--ignored', '--exact', '--nocapture'],
                               env=env, check=True, timeout=300)
                print('LEGACY_SYSTEMD_255_EXISTING_OWNER_REFUSAL_CONFIRMED', flush=True)
                subprocess.run(['cargo', 'test', '--offline', '--locked',
                                'admin_enrollment::tests::emulator_enrollment',
                                '--', '--ignored', '--exact', '--nocapture'],
                               env=env, check=True, timeout=300)
                if enrollment == 'bootstrap':
                    subprocess.run(['cargo', 'test', '--offline', '--locked',
                                    'admin_governance::tests::emulator_bootstrap',
                                    '--', '--ignored', '--exact', '--nocapture'],
                                   env=env, check=True, timeout=300)
                    print('ADMIN_BOOTSTRAP_EXISTING_OWNER_SOFTWARE_TPM_PASSED', flush=True)
                    return
                def enrolled_delivery(mode):
                    subprocess.run(['cargo', 'test', '--offline', '--locked',
                                    'admin_enrollment::tests::emulator_enrolled_delivery',
                                    '--', '--ignored', '--exact', '--nocapture'],
                                   env=dict(env, LUMA_TPM_TEST_DELIVERY=mode),
                                   check=True, timeout=300)
                enrolled_delivery('allow')
                command(['tpm2_pcrextend', '-T', transport, '11:sha256=' + '55' * 32])
                enrolled_delivery('deny')
                approve()
                enrolled_delivery('allow')  # same child; newly signed PCR11
                command(['tpm2_pcrextend', '-T', transport, '7:sha256=' + '66' * 32])
                enrolled_delivery('deny')  # signed PCR11 cannot waive PCR7
                print('EXISTING_OWNER_NATIVE_CHECKPOINT_ENROLLMENT_PASSED', flush=True)
                return
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
