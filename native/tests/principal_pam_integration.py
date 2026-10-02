#!/usr/bin/env python3
"""Targeted real PAM/principal binding in a fresh disposable test container.

No TPM emulator, VM, model runtime or host account is used by this fixture.
"""
import os
from pathlib import Path
import pwd
import subprocess
import tempfile


def main():
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('requires a new disposable root container')
    for path in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock', '/run/luma-build-docker.sock'):
        if Path(path).exists():
            raise SystemExit('unexpected host device or daemon access')
    for lookup, value in ((pwd.getpwnam, 'luma-auth-test'), (pwd.getpwuid, 32001)):
        try:
            lookup(value)
        except KeyError:
            continue
        raise SystemExit('refusing pre-existing fixture account')
    repo = Path(__file__).resolve().parents[2]
    profile = Path('/etc/pam.d/luma-admin')
    with profile.open('xb') as stream:
        stream.write((repo / 'native/image/overlay/etc/pam.d/luma-admin').read_bytes())
    profile.chmod(0o644)
    with tempfile.TemporaryDirectory(prefix='luma-tpm-principal-') as temporary:
        work = Path(temporary)
        password = os.urandom(32).hex().encode('ascii')
        secret = work / 'account-password'
        with secret.open('xb') as stream:
            stream.write(password)
        secret.chmod(0o600)
        environment = {**os.environ, 'LUMA_TPM_TEST_DIRECTORY':str(work)}

        def run(arguments):
            subprocess.run(arguments, check=True, timeout=90, env=environment)

        run(['useradd', '--uid', '32001', '--no-create-home', '--shell', '/bin/bash', 'luma-auth-test'])
        subprocess.run(['chpasswd'], input=b'luma-auth-test:' + password + b'\n', check=True, timeout=30)
        check = ['cargo', 'test', '--offline', '--locked', 'authentication::tests::local_pam_account',
                 '--', '--ignored', '--exact']
        environment['LUMA_PAM_TEST_MODE'] = 'allow'
        run(check)
        environment['LUMA_PAM_TEST_MODE'] = 'deny'
        run(['usermod', '--lock', 'luma-auth-test'])
        run(check)
        run(['usermod', '--unlock', 'luma-auth-test'])
        run(['chage', '--expiredate', '1', 'luma-auth-test'])
        run(check)
        run(['chage', '--expiredate', '-1', 'luma-auth-test'])
        run(['chage', '--lastday', '0', 'luma-auth-test'])
        run(check)
        run(['chage', '--lastday', '20000', 'luma-auth-test'])
        run(['usermod', '--shell', '/usr/sbin/nologin', 'luma-auth-test'])
        run(check)
        run(['usermod', '--shell', '/bin/bash', 'luma-auth-test'])
        profile.write_bytes(b'auth sufficient pam_permit.so\naccount sufficient pam_permit.so\n')
        run(check)
    print('PRINCIPAL_PAM_CASES_PASSED=6 product_admin_enrolled=false image_tested=false', flush=True)


if __name__ == '__main__':
    main()
