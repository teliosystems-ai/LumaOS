#!/usr/bin/env python3
"""Independent resource authority tests on fresh disposable software TPMs only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


CASES = (
    'tpm::tests::emulator_admin_and_resource_authorities_have_independent_handles_and_secrets',
    'resource_checkpoint::tests::emulator_resource_enrollment_sealed_restart_and_exact_extend',
    'resource_checkpoint::tests::emulator_resource_lost_publication_is_explicit_finalize_without_nv_replay',
    'resource_checkpoint::tests::emulator_resource_parent_lost_reply_reconciles_predispatch_name_without_persistence_replay',
)


def require_single_execution(test, output):
    starts = re.findall(r'^running (\d+) tests?$', output, re.MULTILINE)
    summaries = re.findall(
        r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
        r'(\d+) measured; \d+ filtered out; finished in .+$', output, re.MULTILINE)
    if (starts != ['1'] or summaries != [('1', '0', '0', '0')]
            or not re.search(r'^test ' + re.escape(test) + r' \.\.\. ok$', output, re.MULTILINE)):
        raise RuntimeError('expected exactly one executed and passed named resource TPM test: ' + test)


def run_case(test):
    with tempfile.TemporaryDirectory(prefix='luma-tpm-resource-', dir='/tmp') as folder:
        root = Path(folder)
        (root / 'state').mkdir(mode=0o700)
        owner = os.urandom(32)
        (root / 'owner.binary').write_bytes(owner)
        (root / 'owner.tools').write_text('hex:' + owner.hex(), encoding='ascii')
        transport = f'swtpm:path={root}/tpm.sock'
        env = dict(os.environ, TSS2_LOG='all+NONE', LUMA_TPM_TEST_DIRECTORY=str(root))
        env.pop('TSS2_TCTI', None)
        env.pop('TPM2TOOLS_TCTI', None)

        def command(*args):
            result = subprocess.run([str(arg) for arg in args], env=env,
                                    timeout=60, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
            if result.returncode:
                raise RuntimeError(f'{args[0]} refused ({result.returncode}): '
                                   + result.stderr.decode('utf-8', 'replace')[:1200])

        emulator = subprocess.Popen([
            'swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}/state,mode=0600',
            '--server', f'type=unixio,path={root}/tpm.sock',
            '--ctrl', f'type=unixio,path={root}/tpm.sock.ctrl',
            '--flags', 'not-need-init,startup-clear'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not (root / 'tpm.sock.ctrl').exists():
                if emulator.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('disposable resource TPM failed to start')
                time.sleep(.02)
            # Establish ownership exclusively on this freshly spawned emulator.
            # No production boundary contains HierarchyChangeAuth or TPM clear.
            command('tpm2_changeauth', '-T', transport, '-c', 'o', f'file:{root}/owner.tools')
            command('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                    'rsa_keygen_bits:2048', '-out', root / 'private.pem')
            command('openssl', 'rsa', '-in', root / 'private.pem', '-pubout',
                    '-out', root / 'pcr-public.pem')
            command('openssl', 'rsa', '-in', root / 'private.pem', '-RSAPublicKey_out',
                    '-outform', 'DER', '-out', root / 'public.der')
            command('tpm2_startauthsession', '-T', transport, '-S', root / 'session')
            try:
                command('tpm2_policypcr', '-T', transport, '-S', root / 'session',
                        '-l', 'sha256:11', '-L', root / 'signed.policy')
            finally:
                command('tpm2_flushcontext', '-T', transport, root / 'session')
            command('openssl', 'dgst', '-sha256', '-sign', root / 'private.pem',
                    '-out', root / 'signature', root / 'signed.policy')
            (root / 'pcr-signature.json').write_text(json.dumps({'sha256': [{
                'pcrs': [11],
                'pkfp': hashlib.sha256((root / 'public.der').read_bytes()).hexdigest(),
                'pol': (root / 'signed.policy').read_bytes().hex(),
                'sig': base64.b64encode((root / 'signature').read_bytes()).decode('ascii'),
            }]}), encoding='ascii')
            print('RESOURCE_TPM_CASE=' + test, flush=True)
            result = subprocess.run(['cargo', 'test', '--offline', '--locked', test,
                                     '--', '--ignored', '--exact', '--nocapture'],
                                    env=env, timeout=300, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding='utf-8')
            print(result.stdout, end='', flush=True)
            if result.returncode:
                raise RuntimeError(f'resource TPM test failed ({result.returncode}): {test}')
            require_single_execution(test, result.stdout)
            for capability in ('handles-transient', 'handles-loaded-session', 'handles-saved-session'):
                result = subprocess.run(['tpm2_getcap', '-T', transport, capability],
                                        env=env, check=True, timeout=30,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                lines = result.stdout.decode('ascii').splitlines()
                if any(not re.fullmatch(r'- 0x[0-9a-fA-F]{8}', line) for line in lines) or lines:
                    raise RuntimeError('resource operation leaked owned TPM objects or sessions')
            return {'test': test, 'passed': True, 'transport': 'disposable-swtpm'}
        finally:
            if emulator.poll() is None:
                emulator.terminate()
                try:
                    emulator.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    emulator.kill()
                    emulator.wait(timeout=10)


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('fresh isolated root container without host TPM/docker socket required')
    if not os.environ.get('CARGO_TARGET_DIR'):
        raise SystemExit('explicit external build/cache target required; no code-tree artifacts')
    os.umask(0o077)
    results = [run_case(test) for test in CASES]
    print(json.dumps({'schema_version': 1, 'status': 'RESOURCE_CHECKPOINT_SOFTWARE_TPM_PASSED',
                      'physical_qualification': False, 'cases': results}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
