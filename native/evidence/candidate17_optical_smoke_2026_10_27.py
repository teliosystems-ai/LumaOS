#!/usr/bin/env python3
"""Sequence-17 disposable optical (El Torito EFI) live-boot smoke.

Verifier-only harness. It imports the frozen sequence-17 VM fixtures from /repo
unchanged and attaches only the exported ISO as one read-only AHCI CD: no disk,
network, physical device, KVM or host TPM. Live console checks are not
installation, graphical, physical-optical-drive or firmware-vendor evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, '/repo/native/image')
from vm_test import VM, TEST_SOURCES  # noqa: E402
from vm_tpm import SoftwareTPM, state_directory  # noqa: E402
from vm_memory import admit_guest  # noqa: E402
from vm_shutdown import poweroff  # noqa: E402

OWNER = 'd89f6f4e-6249-4fc4-ad4e-4d10f21e83ef'
MEMORY_MIB = 4096


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class OpticalVM(VM):
    """VM fixture methods with an optical-only device inventory."""

    def __init__(self, iso: Path, certificate: Path, work: Path, timeout: int, acceleration: str):
        self.host_memory_admission = admit_guest(MEMORY_MIB)
        print('VM host memory admission: ' + json.dumps(self.host_memory_admission), flush=True)
        self.work = work
        work.mkdir()
        self.socket_directory = tempfile.TemporaryDirectory(prefix='luma-vm-', dir='/tmp')
        self.socket_dir = Path(self.socket_directory.name)
        variables = work.parent/'firmware.fd'
        if variables.exists():
            raise RuntimeError('fresh virtual firmware variables required')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        self.secure_boot = True
        subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', str(certificate),
                        '-out', str(work/'public-cert.pem')], check=True)
        cert = str(work/'public-cert.pem')
        subprocess.run(['virt-fw-vars', '--inplace', str(variables), '--set-pk', OWNER, cert,
                        '--add-kek', OWNER, cert, '--add-db', OWNER, cert, '--sb'], check=True)
        firmware = '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd'
        if acceleration != 'tcg':
            raise ValueError('this smoke admits software emulation only')
        self.acceleration = acceleration
        self.memory_mib = MEMORY_MIB
        command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', str(MEMORY_MIB), '-smp', '2',
                   '-cpu', 'max',
                   '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}',
                   '-drive', f'if=pflash,format=raw,file={variables}',
                   '-drive', f'if=none,id=optical,media=cdrom,readonly=on,format=raw,file={iso}',
                   '-device', 'ide-cd,drive=optical,bus=ide.0,bootindex=1',
                   '-nic', 'none', '-display', 'none', '-monitor', 'none',
                   '-serial', f'unix:{self.socket_dir}/console.sock,server=on,wait=off',
                   '-qmp', f'unix:{self.socket_dir}/qmp.sock,server=on,wait=off', '-no-reboot']
        self.command = command
        self.tpm = self.process = self.errors = self.log = self.console = None
        try:
            self.tpm = SoftwareTPM(state_directory(work.parent))
            command += self.tpm.qemu_arguments()
            self.errors = (work/'qemu.log').open('wb')
            self.process = subprocess.Popen(command, stdout=self.errors, stderr=self.errors)
            self.log = (work/'serial.log').open('wb')
            self.buffer = b''
            self.counter = 0
            self.deadline = time.monotonic()+timeout
            import socket
            self.console = socket.socket(socket.AF_UNIX)
            while not (self.socket_dir/'console.sock').exists():
                if self.process.poll() is not None:
                    raise RuntimeError((work/'qemu.log').read_text())
                if time.monotonic() > self.deadline:
                    raise TimeoutError('QEMU startup')
                time.sleep(.1)
            self.console.connect(str(self.socket_dir/'console.sock'))
        except BaseException:
            self.close()
            raise


REQUIRED = [
    ('optical-live-command-line',
     'grep -qw luma.media=optical /proc/cmdline && grep -qw luma.mode=live /proc/cmdline '
     '&& grep -qw luma.slot=live /proc/cmdline'),
    ('only-optical-loop-and-dm-block-devices',
     'test -z "$(ls /sys/class/block | grep -Ev \'^(loop[0-9]+|sr0|dm-[0-9]+|zram[0-9]+)$\')" '
     '&& test "$(cat /sys/class/block/sr0/device/type)" = 5 && test "$(cat /sys/class/block/sr0/ro)" = 1'),
    ('verity-root', 'test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root'),
    ('optical-media-bind-mount',
     'systemctl is-active media-luma.mount && test "$(findmnt -n -o FSTYPE /media/luma)" = iso9660 '
     '&& test -s /media/luma/release.json && test -s /media/luma/release.sig'),
    ('inventory', 'luma-platform inventory'),
    ('status', 'luma-platform status'),
    ('broker-and-reference-active', 'systemctl is-active luma-broker.service luma-reference.service'),
    ('reference-apparmor-enforce', 'grep -Fx "luma-reference (enforce)" /sys/kernel/security/apparmor/profiles'),
    ('guest-secure-boot-enabled',
     'test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c '
     '| tr -d \' \\n\')" = 1'),
    ('tpm-probe', 'stat -c "%F %u %g %a" /dev/tpmrm0 && luma-platform tpm-probe'),
]

OBSERVED = [
    ('loop-inventory', 'losetup --list --noheadings --output NAME,RO,BACK-FILE'),
    ('verity-status', 'veritysetup status root'),
    ('media-mount', 'findmnt -n -o SOURCE,FSTYPE,OPTIONS /media/luma'),
    ('signed-media-verify', 'luma-platform verify /media/luma'),
]


def observe(vm, command):
    vm.counter += 1
    marker = f'__LUMA_OBS_{vm.counter}'
    vm.send(command+f'; printf "\\n{marker}=%s__\\n" "$?"')
    result = vm.expect(rb'\r?\n'+marker.encode()+rb'=\d+__\r?\n', 1800)
    code = int(re.search(marker.encode()+rb'=(\d+)__', result).group(1))
    return code, hashlib.sha256(result).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--iso-sha256', required=True)
    parser.add_argument('--certificate-sha256', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    iso = args.iso.resolve(strict=True)
    certificate = iso.parent/'secureboot.cer'
    work = args.work.resolve()
    if not iso.is_file() or not iso.is_relative_to('/work/artifacts') or iso.suffix != '.iso':
        raise SystemExit('only the generated ISO under /work/artifacts is accepted')
    if work.parent != Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-<run> directory')
    if not re.fullmatch('[0-9a-f]{64}', args.iso_sha256) or not re.fullmatch('[0-9a-f]{64}', args.certificate_sha256):
        raise SystemExit('exact SHA-256 pins required')
    if file_sha256(certificate) != args.certificate_sha256:
        raise SystemExit('public Secure Boot certificate differs from its pin')
    print('Hashing ISO before boot', flush=True)
    if file_sha256(iso) != args.iso_sha256:
        raise SystemExit('ISO differs from its verified pin before boot')
    work.mkdir()
    record = dict(schema_version=1, purpose='luma-optical-live-boot-smoke-v1', result='failed',
                  iso=str(iso), iso_sha256=args.iso_sha256, acceleration='tcg', uefi=True,
                  secure_boot_tested=True, guest_memory_mib=MEMORY_MIB, network=False,
                  attached_block_devices=['read-only AHCI CD carrying the ISO'],
                  required_checks={}, observations={}, clean_shutdown=None,
                  installation_tested=False, graphical_session_tested=False,
                  physical_optical_drive_tested=False, physical_hardware_tested=False,
                  gate_closing=False, test_sources=TEST_SOURCES,
                  harness_sha256=file_sha256(Path(__file__)))
    vm = None
    try:
        vm = OpticalVM(iso, certificate, work/'optical-live', args.timeout, 'tcg')
        record['host_memory_admission'] = vm.host_memory_admission
        record['qemu_command'] = vm.command
        vm.expect(rb'root@[^\r\n]*[#]', 1800)
        for name, command in REQUIRED:
            print('Optical check: '+name, flush=True)
            vm.run(command, timeout=600)
            record['required_checks'][name] = 'passed'
        for name, command in OBSERVED:
            code, digest = observe(vm, command)
            record['observations'][name] = dict(exit_code=code, transcript_sha256=digest)
        try:
            poweroff(vm, True)
            record['clean_shutdown'] = 'passed'
        except RuntimeError as error:
            record['clean_shutdown'] = 'failed: '+str(error)
            raise
        record['result'] = 'passed'
    except BaseException as error:
        record['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if vm is not None:
            vm.close()
        record['iso_sha256_after'] = file_sha256(iso)
        record['iso_unchanged'] = record['iso_sha256_after'] == args.iso_sha256
        if not record['iso_unchanged']:
            record['result'] = 'failed'
        (work/'result.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
        print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
