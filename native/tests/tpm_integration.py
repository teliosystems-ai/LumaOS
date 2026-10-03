#!/usr/bin/env python3
"""Exercise the native checkpoint adapter on a disposable software TPM only."""
import argparse
import base64
import hashlib
import importlib.util
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
        (work / 'journal.json').write_text(json.dumps(
            {'schema_version': 1, 'deployment': domain, 'entries': []},
            separators=(',', ':')), encoding='utf-8')
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

            def sign_pcr_policy():
                # Explicitly own/flush the trial session. Repeated convenience
                # createpolicy invocations exhaust sessions with direct swtpm
                # transport (there is no kernel resource manager in this lab).
                run(['tpm2_startauthsession', '-T', transport, '-S', work/'policy-session'])
                try:
                    run(['tpm2_policypcr', '-T', transport, '-S', work/'policy-session',
                         '-l', 'sha256:11', '-L', work/'pcr-policy'])
                finally:
                    run(['tpm2_flushcontext', '-T', transport, work/'policy-session'])
                run(['openssl', 'dgst', '-sha256', '-sign', work/'pcr-private.pem',
                     '-out', work/'pcr-signature', work/'pcr-policy'])
                policy = (work/'pcr-policy').read_bytes()
                fingerprint = hashlib.sha256((work/'pcr-public.der').read_bytes()).hexdigest()
                signature = base64.b64encode((work/'pcr-signature').read_bytes()).decode('ascii')
                (work/'pcr-signature.json').write_text(json.dumps({'sha256':[
                    {'pcrs':[11], 'pkfp':fingerprint, 'pol':policy.hex(), 'sig':signature}]}), encoding='utf-8')

            def credential(mode):
                environment['LUMA_TPM_TEST_SEAL'] = mode
                run(['cargo', 'test', '--offline', '--locked', 'sealed_credential::tests::emulator_signed_credential',
                     '--', '--ignored', '--exact', '--nocapture'])

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
            # Real PAM/shadow account checks, confined to this fresh container.
            # Never create, expire or lock an account on the Windows/WSL host.
            pam_profile = Path('/etc/pam.d/luma-admin')
            with pam_profile.open('xb') as stream:
                stream.write((repo/'native/image/overlay/etc/pam.d/luma-admin').read_bytes())
            pam_profile.chmod(0o644)
            account_password = os.urandom(32).hex().encode('ascii')
            (work/'account-password').write_bytes(account_password)
            run(['useradd', '--uid', '32001', '--no-create-home', '--shell', '/bin/bash', 'luma-auth-test'])
            subprocess.run(['chpasswd'], input=b'luma-auth-test:' + account_password + b'\n',
                           check=True, stdout=log, stderr=subprocess.STDOUT, timeout=30)
            pam_test = ['cargo', 'test', '--offline', '--locked', 'authentication::tests::local_pam_account',
                        '--', '--ignored', '--exact', '--nocapture']
            environment['LUMA_PAM_TEST_MODE'] = 'allow'
            run(pam_test)
            environment['LUMA_PAM_TEST_MODE'] = 'deny'
            run(['usermod', '--lock', 'luma-auth-test'])
            run(pam_test)
            run(['usermod', '--unlock', 'luma-auth-test'])
            run(['chage', '--expiredate', '1', 'luma-auth-test'])
            run(pam_test)
            run(['chage', '--expiredate', '-1', 'luma-auth-test'])
            run(['chage', '--lastday', '0', 'luma-auth-test'])
            run(pam_test)
            run(['chage', '--lastday', str(int(time.time() // 86400)), 'luma-auth-test'])
            run(['usermod', '--shell', '/usr/sbin/nologin', 'luma-auth-test'])
            run(pam_test)
            run(['usermod', '--shell', '/bin/bash', 'luma-auth-test'])
            expected_pam = pam_profile.read_bytes()
            pam_profile.write_bytes(b'auth sufficient pam_permit.so\naccount sufficient pam_permit.so\n')
            run(pam_test)
            pam_profile.write_bytes(expected_pam)
            # Disposable PCR-policy signer, distinct from release/firmware
            # keys; never exported and never used for production approval.
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', work/'pcr-private.pem'])
            run(['openssl', 'rsa', '-in', work/'pcr-private.pem', '-pubout', '-out', work/'pcr-public.pem'])
            run(['openssl', 'rsa', '-in', work/'pcr-private.pem', '-RSAPublicKey_out', '-outform', 'DER', '-out', work/'pcr-public.der'])
            sign_pcr_policy()
            credential('seal')
            # New measured kernel without a signature is denied; an approved
            # new measurement can open the SAME sealed credential (no reseal).
            run(['tpm2_pcrextend', '-T', transport, '11:sha256=' + '55'*32])
            credential('deny')
            sign_pcr_policy()
            credential('allow')
            # A signature under a different private key must fail even when
            # its JSON falsely claims the enrolled signer's fingerprint.
            approved_signature = (work/'pcr-signature.json').read_bytes()
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', work/'wrong-private.pem'])
            run(['openssl', 'dgst', '-sha256', '-sign', work/'wrong-private.pem',
                 '-out', work/'wrong-signature', work/'pcr-policy'])
            wrong = json.loads(approved_signature)
            wrong['sha256'][0]['sig'] = base64.b64encode((work/'wrong-signature').read_bytes()).decode('ascii')
            (work/'pcr-signature.json').write_text(json.dumps(wrong), encoding='utf-8')
            credential('deny')
            (work/'pcr-signature.json').write_bytes(approved_signature)
            credential('allow')
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
            # PCR11 returns to the startup value; re-approve that measurement
            # using the same fixture signer, not a new sealed credential.
            sign_pcr_policy()
            credential('allow')
            run(['tpm2_pcrextend', '-T', transport, '7:sha256=' + '66'*32])
            credential('deny')
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
            # Replace only the disposable emulator. Matching startup PCRs and
            # a valid policy signature cannot unlock a different TPM's blob.
            emulator.terminate(); emulator.wait(timeout=10); emulator = None
            for name in ('tpm.sock', 'tpm.sock.ctrl'):
                endpoint = work / name
                if endpoint.exists(): endpoint.unlink()
            state = work / 'replacement-state'
            state.mkdir()
            emulator = start()
            sign_pcr_policy()
            credential('deny')
            # Exercise the SAME policy builder used by image assembly, then
            # replay its measured section/phase events into the software TPM.
            # The small PE fixture is not a bootable Linux OS and this is not
            # guest-boot evidence. No predicted hash is directly assigned to PCR.
            spec = importlib.util.spec_from_file_location('boot_policy', repo/'native/image/boot_policy.py')
            boot_policy = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(boot_policy)
            run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-sha256', '-days', '1', '-subj', '/CN=Disposable UKI TPM Test/',
                 '-keyout', work/'sb.key', '-out', work/'sb.pem'])
            (work/'fixture-initrd').write_bytes(b'not-a-bootable-initrd\n')
            uki_sections = {}
            uki_records = []
            for slot in ('a', 'b'):
                image = work/f'{slot}.efi'
                run(['/usr/lib/systemd/ukify', 'build', '--config', '/dev/null',
                     '--linux', '/usr/lib/systemd/boot/efi/linuxx64.efi.stub',
                     '--initrd', work/'fixture-initrd', '--uname', 'fixture-1',
                     '--cmdline', f'luma.slot={slot} luma.mode=installed',
                     '--os-release', 'ID=luma-test\n', '--no-sign-kernel',
                     '--secureboot-private-key', work/'sb.key', '--secureboot-certificate', work/'sb.pem',
                     *boot_policy.signing_arguments(slot, work/'pcr-private.pem', work/'pcr-public.pem'),
                     '--output', image])
                uki_records.append(boot_policy.verify_uki(image, slot, (work/'pcr-public.pem').read_bytes(), work/'sb.pem'))
                uki_sections[slot] = boot_policy.read_sections(image)

            def extend_pcr_event(value):
                run(['tpm2_pcrextend', '-T', transport, '11:sha256=' + hashlib.sha256(value).hexdigest()])

            def measure_sections(slot):
                sections = uki_sections[slot]
                (work/'pcr-signature.json').write_bytes(sections['.pcrsig'])
                for name in boot_policy.SECTIONS:
                    if '.' + name in sections:
                        extend_pcr_event(('.' + name).encode('ascii') + b'\0')
                        extend_pcr_event(sections['.' + name])

            def check_measured_policy(slot):
                run(['tpm2_pcrread', '-T', transport, 'sha256:11', '-o', work/'observed-pcr'])
                observed = (work/'observed-pcr').read_bytes()
                if boot_policy.policy_digest(observed.hex()) not in uki_records[0 if slot == 'a' else 1]['policy_digests']:
                    raise RuntimeError('actual TPM replay differs from UKI measurement prediction')

            measure_sections('a')
            for phase in ('enter-initrd', 'leave-initrd', 'sysinit'):
                extend_pcr_event(phase.encode('ascii'))
            check_measured_policy('a')
            credential('seal')
            sealed_digest = hashlib.sha256((work/'credential.cred').read_bytes()).digest()
            extend_pcr_event(b'ready')
            check_measured_policy('a')
            credential('allow')
            extend_pcr_event(b'shutdown')
            credential('deny')
            run(['tpm2_shutdown', '-T', transport, '-c'])
            emulator.terminate(); emulator.wait(timeout=10); emulator = None
            for name in ('tpm.sock', 'tpm.sock.ctrl'):
                endpoint = work / name
                if endpoint.exists(): endpoint.unlink()
            emulator = start()
            measure_sections('b')
            extend_pcr_event(b'enter-initrd')
            credential('deny')
            for phase in ('leave-initrd', 'sysinit'):
                extend_pcr_event(phase.encode('ascii'))
            check_measured_policy('b')
            credential('allow')
            if hashlib.sha256((work/'credential.cred').read_bytes()).digest() != sealed_digest:
                raise RuntimeError('A/B fixture must not reseal the credential')
            extend_pcr_event(b'unapproved-measurement')
            credential('deny')
            (args.output/'uki-policy.json').write_text(json.dumps({'schema_version':1,
                'fixture':'synthetic-nonbootable-pe', 'guest_boot_tested':False,
                'actual_tpm_event_replay_tested':True, 'slots':uki_records,
                'gate_closing':False}, indent=2)+'\n', encoding='utf-8')
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
                       'binary-authorization-with-nul-cr-lf',
                       'tpm-only-signed-pcr-credential-roundtrip',
                       'credential-deployment-substitution-refusal',
                       'credential-payload-tamper-refusal',
                       'credential-public-key-substitution-refusal',
                       'credential-missing-signature-refusal',
                       'unapproved-pcr11-refusal', 'approved-pcr11-update-without-reseal',
                       'wrong-policy-signature-refusal',
                       'sealed-credential-tpm-restart-persistence',
                       'changed-pcr7-refusal', 'replacement-tpm-credential-refusal',
                       'uki-measurement-prediction-matches-tpm-event-replay',
                       'uki-sysinit-credential-roundtrip', 'uki-ready-phase-credential-allow',
                       'uki-shutdown-phase-refusal', 'uki-initrd-phase-refusal',
                       'uki-ab-credential-continuity-without-reseal', 'uki-unapproved-event-refusal',
                       'native-pam-account-authentication', 'wrong-password-refusal',
                       'root-account-refusal', 'locked-account-refusal', 'expired-account-refusal',
                       'nologin-account-refusal', 'password-change-required-refusal',
                       'empty-password-refusal', 'unknown-account-refusal', 'pam-profile-substitution-refusal'],
              'sealed_credential_primitive_tested':True,
              'physical_tpm_tested':False, 'sealed_credential_enrollment_tested':False,
              'production_admin_authorization_tested':False, 'gate_closing':False}
    transcript = args.output/'transcript.txt'
    record['transcript_sha256'] = hashlib.sha256(transcript.read_bytes()).hexdigest()
    record['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (args.output/'result.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
