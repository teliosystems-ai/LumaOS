#!/usr/bin/env python3
"""Exercise the native checkpoint adapter on a disposable software TPM only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').is_file() or os.geteuid() != 0 or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists():
        raise SystemExit('use a fresh disposable tools container with no physical TPM devices')
    if args.output.exists():
        raise SystemExit('evidence output must be new')
    args.output.mkdir(parents=True)
    repo = args.repository.resolve(strict=True)
    os.umask(0o077)
    environment = dict(os.environ, CARGO_TARGET_DIR='/tmp/luma-tpm-target',
                       RUSTFLAGS='-Dwarnings', TSS2_LOG='all+NONE')
    with tempfile.TemporaryDirectory(prefix='luma-tpm-') as folder:
        work = Path(folder)
        state = work / 'state'
        state.mkdir()
        auth = work / 'auth'
        # The tools' file: authorization parser reads TEXT, including hex:;
        # raw binary containing NUL/CR/LF would be truncated/trimmed. Keep the
        # native credential binary and a separate private tools-only encoding.
        # Force those bytes in this TEST fixture to make the regression stable.
        auth_bytes = bytearray(os.urandom(32))
        auth_bytes[10] = 0
        auth_bytes[-2:] = b'\r\n'
        auth.write_bytes(auth_bytes)
        tools_auth = work / 'auth-tools'
        tools_auth.write_text('hex:' + auth_bytes.hex(), encoding='ascii')
        domain = 'ab' * 32
        genesis = hashlib.sha256(b'luma-native-admin-genesis-v1\0' + bytes.fromhex(domain)).digest()
        (work / 'genesis').write_bytes(genesis)
        (work / 'journal.json').write_text(json.dumps({'schema_version':1, 'deployment':domain, 'entries':[]}), encoding='utf-8')
        transport = f'swtpm:path={work}/tpm.sock'
        environment['LUMA_TPM_TEST_DIRECTORY'] = str(work)
        emulator = None
        log = (args.output / 'transcript.txt').open('wb')
        try:
            def run(argv, expected=0):
                print('TPM test: ' + Path(argv[0]).name + ' ' + str(argv[1]), flush=True)
                result = subprocess.run([str(a) for a in argv], cwd=repo/'rust', env=environment,
                                        stdout=log, stderr=subprocess.STDOUT, timeout=240)
                if result.returncode != expected:
                    raise RuntimeError(f'{Path(argv[0]).name} returned {result.returncode}, expected {expected}')

            def start():
                process = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state},mode=0600',
                    '--server', f'type=unixio,path={work}/tpm.sock',
                    '--ctrl', f'type=unixio,path={work}/tpm.sock.ctrl',
                    '--flags', 'not-need-init,startup-clear'], stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while not (work / 'tpm.sock.ctrl').exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        process.kill(); process.wait()
                        raise RuntimeError('software TPM did not start')
                    time.sleep(.02)
                return process

            emulator = start()
            environment['LUMA_TPM_TEST_ADMISSION'] = 'free'
            admission = ['cargo', 'test', '--offline', '--locked',
                         'tpm::tests::emulator_install_admission',
                         '--', '--ignored', '--exact', '--nocapture']
            run(admission)
            run(['tpm2_nvdefine', '-T', transport, '-C', 'o', '-g', 'sha256', '-s', '32',
                 '-a', '0x02040044', '-p', f'file:{tools_auth}', '0x01804c41'])
            # Password-session provisioning is deliberately confined to this
            # disposable test fixture; the native adapter uses HMAC sessions.
            run(['tpm2_nvextend', '-T', transport, '-C', '0x01804c41', '-P', f'file:{tools_auth}',
                 '-i', work/'genesis', '0x01804c41'])
            environment['LUMA_TPM_TEST_ADMISSION'] = 'occupied'
            run(admission)
            run(['cargo', 'test', '--offline', '--locked', '--', '--nocapture'])
            run(['cargo', 'test', '--offline', '--locked', 'tpm::tests::emulator_nv_journal_and_rollback',
                 '--', '--ignored', '--exact', '--nocapture'])
            run(['tpm2_shutdown', '-T', transport, '-c'])
            emulator.terminate(); emulator.wait(timeout=10); emulator = None
            # Remove only the stopped fixture's two exact socket names. State,
            # auth and journal remain for the restart test, not regenerated.
            for name in ('tpm.sock', 'tpm.sock.ctrl'):
                endpoint = work / name
                if endpoint.exists(): endpoint.unlink()
            emulator = start()
            run(['cargo', 'test', '--offline', '--locked', 'tpm::tests::emulator_restart_and_external_change',
                 '--', '--ignored', '--exact', '--nocapture'])
            # Delete/redefine only this container's freshly created emulator
            # index. These commands are never exposed by the product adapter.
            run(['tpm2_nvundefine', '-T', transport, '-C', 'o', '0x01804c41'])
            refused = ['cargo', 'test', '--offline', '--locked',
                       'tpm::tests::emulator_rejects_missing_or_redefined_index',
                       '--', '--ignored', '--exact', '--nocapture']
            run(refused)
            run(['tpm2_nvdefine', '-T', transport, '-C', 'o', '-g', 'sha256', '-s', '32',
                 '-a', '0x02040004', '-p', f'file:{tools_auth}', '0x01804c41'])
            run(['tpm2_nvwrite', '-T', transport, '-C', '0x01804c41', '-P', f'file:{tools_auth}',
                 '-i', work/'genesis', '0x01804c41'])
            run(refused)
            run(['cargo', 'build', '--offline', '--locked'])
            binary = '/tmp/luma-tpm-target/debug/luma-platform'
            # Even when a reachable emulator is advertised in the usual tool
            # environment, the installed path insists on /dev/tpmrm0.
            environment['TPM2TOOLS_TCTI'] = transport
            environment['TSS2_TCTI'] = transport
            run([binary, 'tpm-probe'], expected=1)
            run([binary, 'admin-install-check'], expected=1)
            run([binary, 'admin-checkpoint-status'], expected=1)
        finally:
            if emulator is not None:
                emulator.terminate()
                try: emulator.wait(timeout=10)
                except subprocess.TimeoutExpired: emulator.kill(); emulator.wait()
            log.close()
    record = {'schema_version':1, 'result':'passed', 'profile':'local-tpm2',
              'environment':'isolated-swtpm-container', 'kernel':platform.release(),
              'cases':['authenticated-nv-read-and-extend', 'exact-name-pinning', 'wrong-auth-refusal',
                       'sole-writer-lock', 'stale-checkpoint-refusal', 'sixteen-durable-audit-appends',
                       'disk-rollback-refusal', 'payload-tamper-refusal', 'missing-journal-refusal',
                       'pending-transaction-refusal', 'nv-persistence-across-tpm-restart',
                       'boot-epoch-expiry', 'unexpected-tpm-advance-refusal',
                       'missing-nv-index-refusal', 'redefined-nv-attributes-refusal',
                       'no-environment-transport-fallback', 'unenrolled-product-status-refusal',
                       'unoccupied-index-admission', 'occupied-index-admission-refusal',
                       'missing-local-tpm-installer-admission-refusal',
                       'binary-authorization-with-nul-cr-lf'],
              'physical_tpm_tested':False, 'sealed_credential_enrollment_tested':False,
              'production_admin_authorization_tested':False, 'gate_closing':False}
    transcript = args.output/'transcript.txt'
    record['transcript_sha256'] = hashlib.sha256(transcript.read_bytes()).hexdigest()
    record['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (args.output/'result.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
