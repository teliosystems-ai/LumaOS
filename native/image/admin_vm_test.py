#!/usr/bin/env python3
"""Booted-image PAM and signed-PCR tests on disposable software-TPM VMs.

Not Admin enrollment or physical TPM qualification. All fixture values are public.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

from vm_test import (ADMIN_PASSWORD, TEST_SOURCES, VM, install, installed_login,
                     live_ready)

PUBLIC_VALUE = 'public-luma-pcr-credential-fixture'
CREDENTIAL = '/var/lib/luma-os/vm-public-credential.cred'
PUBLIC_KEY = '/run/systemd/tpm2-pcr-public-key.pem'
SIGNATURE = '/run/systemd/tpm2-pcr-signature.json'


def authenticate(vm, password, expected):
    vm.send('luma-platform admin-auth-check lumaadmin; printf "\\n__AUTH_RC=%s__\\n" "$?"')
    vm.expect(rb'Account password \(authentication only\):')
    vm.send(password)
    output = vm.expect(rb'\r?\n__AUTH_RC=\d+__\r?\n')
    if password.encode() in output:
        raise RuntimeError('account password echoed on serial console')
    if int(re.search(rb'__AUTH_RC=(\d+)__', output).group(1)) != expected:
        raise RuntimeError('unexpected account authentication result')
    if expected == 0:
        objects = re.findall(rb'\{[^\r\n]*\}', output)
        if len(objects) != 1 or json.loads(objects[0]) != {
            'authenticated_uid': 1001, 'product_admin_active': False,
            'role_grant': False, 'gate_closing': False,
        }:
            raise RuntimeError('authentication incorrectly reported product authority')


def installed_checks(vm):
    installed_login(vm)
    vm.run('luma-platform boot-health')
    vm.run('systemctl is-active systemd-pcrphase-sysinit.service systemd-pcrphase.service')
    vm.run('test "$(systemctl show --value -p Result luma-staging-clean.service)" = success && '
           'test "$(systemctl show --value -p ExecMainStartTimestampMonotonic luma-staging-clean.service)" -gt 0')
    vm.run(f'test -s {SIGNATURE} && cmp {PUBLIC_KEY} /usr/share/luma-os/admin-pcr-public.pem')
    probe = "import json,sys; r=json.load(sys.stdin); assert r['transport']=='device:/dev/tpmrm0' and not r['enrolled'] and not r['clock_is_utc']; assert len(r['pcr11_sha256'])==64 and r['pcr11_sha256']!='0'*64"
    vm.run('luma-platform tpm-probe | python3 -c ' + shlex.quote(probe))
    intent = "import json; r=json.load(open('/var/lib/luma-os/admin-install-intent.json')); assert r['profile']=='local-tpm2' and r['candidate_admin_uid']==1001 and not r['product_admin_active'] and r['enrollment_status']=='required'"
    vm.run('python3 -c ' + shlex.quote(intent))
    vm.run('test "$(stat -c %a /usr/libexec/luma-os/luma-auth-helper)" = 700')
    vm.run('runuser -u lumauser -- luma-platform admin-auth-check lumaadmin', expected=1)
    authenticate(vm, ADMIN_PASSWORD, 0)
    authenticate(vm, 'public-incorrect-password-fixture', 1)


def decrypt(vm):
    # Explicit helper/device/policy and expected public fixture; no host-key fallback.
    command = (f'systemd-creds --tpm2-device=/dev/tpmrm0 --name=luma-vm-public '
               f'--tpm2-signature={SIGNATURE} --newline=no decrypt {CREDENTIAL} -')
    vm.run('test "$('+command+')" = '+shlex.quote(PUBLIC_VALUE))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--secure-boot', action='store_true')
    parser.add_argument('--accel', choices=('auto', 'kvm', 'tcg'), default='auto')
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    work = args.work.resolve()
    if not image.is_file() or not image.is_relative_to('/work/artifacts'):
        raise SystemExit('only generated regular-file media under /work/artifacts is accepted')
    if work.parent != Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-* directory')
    work.mkdir()
    target = work/'target.qcow2'
    subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(target), '32G'], check=True)
    stages = []
    for name in ('install', 'installed', 'reboot', 'other-slot'):
        print('Admin/PCR VM stage: '+name, flush=True)
        vm = VM(image, work/name, target, name == 'install', args.timeout,
                args.secure_boot, args.accel)
        try:
            if name == 'install':
                live_ready(vm)
                install(vm)
            else:
                installed_checks(vm)
                vm.run('grep -qw luma.slot='+('b' if name == 'other-slot' else 'a')+' /proc/cmdline')
                if name == 'installed':
                    vm.run('umask 077; printf %s '+shlex.quote(PUBLIC_VALUE)+
                           ' | systemd-creds --tpm2-device=/dev/tpmrm0 --name=luma-vm-public '
                           '--with-key=tpm2-with-public-key --tpm2-pcrs=7 '
                           f'--tpm2-public-key-pcrs=11 --tpm2-public-key={PUBLIC_KEY} '
                           f'encrypt - {CREDENTIAL}')
                decrypt(vm)
                if name == 'reboot':
                    select_b = "from pathlib import Path; p=list(Path('/efi/EFI/Linux').glob('luma-b-*.efi')); assert len(p)==1; Path('/efi/loader/loader.conf').write_text('default '+p[0].name+'\\ntimeout 3\\neditor no\\n')"
                    vm.run('python3 -c '+shlex.quote(select_b))
                if name == 'other-slot':
                    # Only mutate the disposable software TPM, after continuity.
                    event = hashlib.sha256(b'luma-vm-unapproved').hexdigest()
                    vm.run('tpm2_pcrextend -T device:/dev/tpmrm0 11:sha256='+event)
                    vm.run(f'systemd-creds --tpm2-device=/dev/tpmrm0 --name=luma-vm-public '
                           f'--tpm2-signature={SIGNATURE} decrypt {CREDENTIAL} /dev/null', expected=1)
            stages.append(name)
            vm.run('sync')
            vm.send('systemctl poweroff')
            if vm.wait_exit() != 0:
                raise RuntimeError('guest poweroff failed')
        finally:
            vm.close()
    with image.open('rb') as stream:
        image_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    record = {'result': 'passed', 'stages': stages, 'image_sha256': image_hash,
              'acceleration': vm.acceleration, 'secure_boot_tested': args.secure_boot,
              'pam_authentication_tested': True, 'measured_boot_credential_tested': True,
              'credential_reboot_continuity_tested': True, 'unapproved_pcr_refusal_tested': True,
              'credential_ab_continuity_tested': True,
              'admin_enrollment_tested': False, 'physical_hardware_tested': False,
              'gate_closing': False, 'test_sources': TEST_SOURCES}
    (work/'result.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
