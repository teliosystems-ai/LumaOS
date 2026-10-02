#!/usr/bin/env python3
"""Disposable TPM proof for an owner-approved persistent parent and signed PCR policy.

This is a test-only protocol experiment. It is not the native credential backend
and never contacts a host TPM or changes product enrollment state.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('isolated root container without host TPM/socket required')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='luma-owner-backend-') as folder:
        root = Path(folder)
        (root / 'state').mkdir()
        transport = f'swtpm:path={root}/tpm.sock'
        env = dict(os.environ, TPM2TOOLS_TCTI=transport, TSS2_LOG='all+NONE')

        def run(*args, okay=True):
            result = subprocess.run([str(value) for value in args], cwd=root, env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    timeout=30)
            if okay and result.returncode:
                raise RuntimeError(f'{args[0]} failed ({result.returncode}): '
                                   + result.stderr.decode('utf-8', 'replace')[:1200])
            return result.returncode == 0

        def start_emulator():
            process = subprocess.Popen([
                'swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state,mode=0600',
                '--server', f'type=unixio,path={root}/tpm.sock',
                '--ctrl', f'type=unixio,path={root}/tpm.sock.ctrl',
                '--flags', 'not-need-init,startup-clear'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 10
            while not (root / 'tpm.sock.ctrl').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('isolated TPM did not start')
                time.sleep(.02)
            return process

        def stop_emulator(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

        emulator = start_emulator()
        try:
            run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                'rsa_keygen_bits:2048', '-out', 'private.pem')
            run('openssl', 'rsa', '-in', 'private.pem', '-pubout', '-out', 'public.pem')
            (root / 'owner.hex').write_text('hex:' + os.urandom(32).hex(), encoding='ascii')
            (root / 'secret').write_bytes(os.urandom(32))
            run('tpm2_changeauth', '-c', 'o', 'file:owner.hex')
            run('tpm2_createprimary', '-C', 'o', '-P', 'file:owner.hex',
                '-G', 'rsa2048', '-c', 'primary.ctx')
            run('tpm2_evictcontrol', '-C', 'o', '-P', 'file:owner.hex',
                '-c', 'primary.ctx', '0x81004c41')
            run('tpm2_readpublic', '-c', '0x81004c41', '-n', 'parent.name')
            run('tpm2_loadexternal', '-G', 'rsa', '-C', 'o', '-u', 'public.pem',
                '-c', 'signer.ctx', '-n', 'signer.name')

            run('tpm2_startauthsession', '-S', 'trial.ctx')
            run('tpm2_policyauthorize', '-S', 'trial.ctx', '-n', 'signer.name',
                '-L', 'authorized.policy')
            run('tpm2_policypcr', '-S', 'trial.ctx', '-l', 'sha256:7',
                '-L', 'combined.policy')
            run('tpm2_flushcontext', 'trial.ctx')
            # tpm2-tools serializes external key contexts differently from
            # session files; clear only this disposable fixture's transients.
            run('tpm2_flushcontext', '-t')
            run('tpm2_create', '-C', '0x81004c41', '-u', 'sealed.pub',
                '-r', 'sealed.priv', '-i', 'secret', '-L', 'combined.policy')

            def sign_current_pcr11():
                run('tpm2_startauthsession', '-S', 'sign.ctx')
                run('tpm2_policypcr', '-S', 'sign.ctx', '-l', 'sha256:11',
                    '-L', 'signed.policy')
                run('tpm2_flushcontext', 'sign.ctx')
                run('openssl', 'dgst', '-sha256', '-sign', 'private.pem',
                    '-out', 'signature', 'signed.policy')

            def unseal():
                run('tpm2_loadexternal', '-G', 'rsa', '-C', 'o', '-u', 'public.pem',
                    '-c', 'signer.ctx')
                try:
                    run('tpm2_verifysignature', '-c', 'signer.ctx', '-g', 'sha256',
                        '-m', 'signed.policy', '-s', 'signature', '-t', 'ticket', '-f', 'rsassa')
                finally:
                    run('tpm2_flushcontext', '-t')
                run('tpm2_startauthsession', '--policy-session', '-S', 'runtime.ctx')
                try:
                    run('tpm2_policypcr', '-S', 'runtime.ctx', '-l', 'sha256:11')
                    if not run('tpm2_policyauthorize', '-S', 'runtime.ctx',
                               '-i', 'signed.policy', '-n', 'signer.name',
                               '-t', 'ticket', okay=False):
                        return False
                    if not run('tpm2_policypcr', '-S', 'runtime.ctx',
                               '-l', 'sha256:7', okay=False):
                        return False
                    run('tpm2_load', '-C', '0x81004c41', '-u', 'sealed.pub',
                        '-r', 'sealed.priv', '-c', 'sealed.ctx')
                    success = run('tpm2_unseal', '-c', 'sealed.ctx',
                                  '-p', 'session:runtime.ctx', '-o', 'unsealed', okay=False)
                    if success and (root / 'unsealed').read_bytes() != (root / 'secret').read_bytes():
                        raise AssertionError('unsealed bytes differ')
                    return success
                finally:
                    run('tpm2_flushcontext', 'runtime.ctx')
                    run('tpm2_flushcontext', '-t')

            sign_current_pcr11()
            assert unseal(), 'owner approved parent must unlock without owner password'
            run('tpm2_loadexternal', '-G', 'rsa', '-C', 'o', '-u', 'public.pem',
                '-c', 'signer.ctx')
            run('tpm2_verifysignature', '-c', 'signer.ctx', '-g', 'sha256',
                '-m', 'signed.policy', '-s', 'signature', '-t', 'valid.ticket', '-f', 'rsassa')
            assert (root / 'valid.ticket').is_file()
            original_signature = (root / 'signature').read_bytes()
            (root / 'signature').write_bytes(bytes([original_signature[0] ^ 1])
                                            + original_signature[1:])
            assert not run('tpm2_verifysignature', '-c', 'signer.ctx',
                           '-g', 'sha256', '-m', 'signed.policy', '-s', 'signature',
                           '-t', 'forged.ticket', '-f', 'rsassa', okay=False), \
                'forged PCR signature must refuse'
            (root / 'signature').write_bytes(original_signature)
            run('tpm2_flushcontext', '-t')
            run('tpm2_pcrextend', '11:sha256=' + '55' * 32)
            assert not unseal(), 'old signed PCR11 must refuse after measurement changes'
            sign_current_pcr11()
            assert unseal(), 'new signed PCR11 must unlock'
            run('tpm2_pcrextend', '7:sha256=' + '66' * 32)
            assert not unseal(), 'PCR7 change must refuse even with valid PCR11 signature'
            run('tpm2_shutdown', '-c')
            stop_emulator(emulator)
            emulator = start_emulator()
            run('tpm2_readpublic', '-c', '0x81004c41', '-n', 'parent-after.name')
            assert (root / 'parent.name').read_bytes() == (root / 'parent-after.name').read_bytes(), \
                'persistent parent name changed after restart'
            assert not run('tpm2_createprimary', '-C', 'o', '-G', 'rsa2048',
                           '-c', 'unauthorized.ctx', okay=False), \
                'owner authorization disappeared after restart'
            sign_current_pcr11()
            assert unseal(), 'persistent parent must unlock after TPM restart'
            print('OWNER_BACKEND_POLICY_FEASIBILITY_PASSED', flush=True)
        finally:
            stop_emulator(emulator)


if __name__ == '__main__':
    main()
