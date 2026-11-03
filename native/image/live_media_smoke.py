#!/usr/bin/env python3
"""Disposable live-boot smoke of one exported medium under emulated Secure Boot.

A generalized successor of native/evidence/candidate19_optical_smoke_2026_10_28.py
(retained unchanged). The owner installs every image from a download, so no
physical optical drive is assumed. The same ten required checks and thirteen
observations (five gated) run against one of three read-only media:

- optical: the exported ISO as one AHCI CD (a VM DVD file), exactly as sequence 19;
- virtio-disk: the exported raw GPT image as one virtio disk (a VM disk file);
- usb-disk: the same raw image as one removable USB mass-storage disk on an
  xHCI controller (a written USB stick).

Only the three medium checks differ: the kernel command line, the block-device
inventory and the media mount. Secure Boot stays on. The firmware variables are
fresh and enroll only the public certificate exported beside the medium as
PK, KEK and db; nothing falls back to a reduced-security boot. TCG only: no
KVM, network, physical device or host TPM. The guest has 8 GiB of RAM because
RAM-backed /var holds at most half of RAM and the desktop payload needs more
than 6732 MiB there. Live console checks are not installation, graphical,
physical-USB, physical-optical-drive or firmware-vendor evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vm_test import VM, TEST_SOURCES  # noqa: E402
from vm_tpm import SoftwareTPM, state_directory  # noqa: E402
from vm_memory import admit_guest  # noqa: E402
from vm_shutdown import poweroff  # noqa: E402

OWNER = 'd89f6f4e-6249-4fc4-ad4e-4d10f21e83ef'
MEMORY_MIB = 8192
CYCLE = re.compile(rb'[Oo]rdering cycle')
MEDIA = ('optical', 'virtio-disk', 'usb-disk')
SUFFIX = {'optical': '.iso', 'virtio-disk': '.img', 'usb-disk': '.img'}
DISK = {'virtio-disk': 'vda', 'usb-disk': 'sda'}
ATTACHED = {
    'optical': 'read-only AHCI CD carrying the ISO',
    'virtio-disk': 'read-only virtio disk carrying the raw GPT image',
    'usb-disk': 'read-only removable USB mass-storage disk on xHCI carrying the raw GPT image',
}
FIRMWARE = '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd'
VARIABLES = '/usr/share/OVMF/OVMF_VARS_4M.fd'


def file_sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def media_arguments(medium, media):
    """QEMU arguments that attach exactly one read-only boot medium."""
    if medium == 'optical':
        return ['-drive', f'if=none,id=optical,media=cdrom,readonly=on,format=raw,file={media}',
                '-device', 'ide-cd,drive=optical,bus=ide.0,bootindex=1']
    if medium == 'virtio-disk':
        return ['-drive', f'if=none,id=media,format=raw,readonly=on,file={media}',
                '-device', 'virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex=1']
    if medium == 'usb-disk':
        return ['-device', 'qemu-xhci,id=xhci',
                '-drive', f'if=none,id=usbstick,format=raw,readonly=on,file={media}',
                '-device', 'usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=1']
    raise ValueError('unknown medium')


def qemu_command(medium, media, variables, socket_dir):
    return ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', str(MEMORY_MIB), '-smp', '2',
            '-cpu', 'max',
            '-drive', f'if=pflash,format=raw,readonly=on,file={FIRMWARE}',
            '-drive', f'if=pflash,format=raw,file={variables}',
            *media_arguments(medium, media),
            '-nic', 'none', '-display', 'none', '-monitor', 'none',
            '-serial', f'unix:{socket_dir}/console.sock,server=on,wait=off',
            '-qmp', f'unix:{socket_dir}/qmp.sock,server=on,wait=off', '-no-reboot']


class LiveMediaVM(VM):
    """VM fixture methods with a one-medium device inventory."""

    def __init__(self, medium: str, media: Path, certificate: Path, work: Path, timeout: int, acceleration: str):
        if acceleration != 'tcg':
            raise ValueError('this smoke admits software emulation only')
        self.host_memory_admission = admit_guest(MEMORY_MIB)
        print('VM host memory admission: ' + json.dumps(self.host_memory_admission), flush=True)
        self.work = work
        work.mkdir()
        self.socket_directory = tempfile.TemporaryDirectory(prefix='luma-vm-', dir='/tmp')
        self.socket_dir = Path(self.socket_directory.name)
        variables = work.parent/'firmware.fd'
        if variables.exists():
            raise RuntimeError('fresh virtual firmware variables required')
        shutil.copyfile(VARIABLES, variables)
        self.secure_boot = True
        subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', str(certificate),
                        '-out', str(work/'public-cert.pem')], check=True)
        cert = str(work/'public-cert.pem')
        subprocess.run(['virt-fw-vars', '--inplace', str(variables), '--set-pk', OWNER, cert,
                        '--add-kek', OWNER, cert, '--add-db', OWNER, cert, '--sb'], check=True)
        self.acceleration = acceleration
        self.memory_mib = MEMORY_MIB
        command = qemu_command(medium, media, variables, self.socket_dir)
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


NO_PAGER = 'export SYSTEMD_PAGER=cat SYSTEMD_LESS= PAGER=cat SYSTEMD_COLORS=0'

OPTICAL_CHECKS = [
    ('optical-live-command-line',
     'grep -qw luma.media=optical /proc/cmdline && grep -qw luma.mode=live /proc/cmdline '
     '&& grep -qw luma.slot=live /proc/cmdline'),
    ('only-optical-loop-and-dm-block-devices',
     'test -z "$(ls /sys/class/block | grep -Ev \'^(loop[0-9]+|sr0|dm-[0-9]+|zram[0-9]+)$\')" '
     '&& test "$(cat /sys/class/block/sr0/device/type)" = 5 && test "$(cat /sys/class/block/sr0/ro)" = 1'),
    ('verity-root', 'test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root'),
    ('optical-media-bind-mount',
     'systemctl --no-pager is-active media-luma.mount && test "$(findmnt -n -o FSTYPE /media/luma)" = iso9660 '
     '&& test -s /media/luma/release.json && test -s /media/luma/release.sig'),
]

COMMON_CHECKS = [
    ('inventory', 'luma-platform inventory'),
    ('status', 'luma-platform status'),
    ('broker-and-reference-active', 'systemctl --no-pager is-active luma-broker.service luma-reference.service'),
    ('reference-apparmor-enforce', 'grep -Fx "luma-reference (enforce)" /sys/kernel/security/apparmor/profiles'),
    ('guest-secure-boot-enabled',
     'test "$(od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c '
     '| tr -d \' \\n\')" = 1'),
    ('tpm-probe', 'stat -c "%F %u %g %a" /dev/tpmrm0 && luma-platform tpm-probe'),
]


def disk_checks(medium):
    """The three medium checks for a live boot from the raw GPT image."""
    disk = DISK[medium]
    bus = ('readlink -f /sys/class/block/vda | grep -q /virtio' if medium == 'virtio-disk' else
           'readlink -f /sys/class/block/sda | grep -q /usb && test "$(cat /sys/class/block/sda/removable)" = 1')
    return [
        # The disk live entry carries no luma.media= option; only the optical entry does.
        ('live-disk-command-line',
         "! grep -q 'luma[.]media=' /proc/cmdline && grep -qw luma.mode=live /proc/cmdline "
         '&& grep -qw luma.slot=live /proc/cmdline'),
        ('only-live-disk-loop-and-dm-block-devices',
         f'test -z "$(ls /sys/class/block | grep -Ev \'^(loop[0-9]+|{disk}|{disk}[0-9]+|dm-[0-9]+|zram[0-9]+)$\')" '
         f'&& test "$(cat /sys/class/block/{disk}/ro)" = 1 '
         f"&& readlink -f /dev/disk/by-partlabel/luma-payload | grep -Ex '/dev/{disk}[0-9]+' && {bus}"),
        ('verity-root', 'test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root'),
        ('live-disk-media-mount',
         'systemctl --no-pager is-active media-luma.mount && test "$(findmnt -n -o FSTYPE /media/luma)" = ext4 '
         "&& findmnt -n -o OPTIONS /media/luma | tr , '\\n' | grep -qx ro "
         '&& test "$(readlink -f "$(findmnt -n -o SOURCE /media/luma)")" '
         '= "$(readlink -f /dev/disk/by-partlabel/luma-payload)" '
         '&& test -s /media/luma/release.json && test -s /media/luma/release.sig'),
    ]


def required_checks(medium):
    return (OPTICAL_CHECKS if medium == 'optical' else disk_checks(medium)) + COMMON_CHECKS


# (name, command, gated, timeout seconds). Gated observations must exit 0 for a pass.
# Guest patterns spell 'ordering[ ]cycle' so the echoed command never matches CYCLE.
OBSERVED = [
    ('failed-units', 'systemctl --no-pager --failed --no-legend --plain', False, 300),
    ('no-failed-units', 'test -z "$(systemctl --no-pager --failed --no-legend --plain)"', True, 300),
    ('recovery-keeper-active', 'systemctl --no-pager is-active luma-utc-recovery-keeper.service', True, 300),
    ('recovery-producer-path-active',
     'systemctl --no-pager is-active luma-utc-recovery-producer.path', True, 300),
    ('utc-units', "systemctl --no-pager --no-legend --plain --all list-units 'luma-utc*'", False, 300),
    ('recovery-keeper-journal',
     'journalctl -b -o short-monotonic --no-pager -u luma-utc-recovery-keeper.service '
     '-u luma-utc-recovery-producer.path -u luma-utc-recovery-producer.service | tail -n 120', False, 300),
    ('no-ordering-cycle-in-journal', "! journalctl -b -o cat --no-pager | grep -Eiq 'ordering[ ]cycle'", True, 600),
    ('ordering-cycle-journal', "journalctl -b -o cat --no-pager | grep -Ei -A3 'ordering[ ]cycle' | head -n 60",
     False, 600),
    ('loop-inventory', 'losetup --list --noheadings --output NAME,RO,BACK-FILE', False, 300),
    ('verity-status', 'veritysetup status root', False, 300),
    ('media-mount', 'findmnt -n -o SOURCE,FSTYPE,OPTIONS /media/luma', False, 300),
    ('memory', 'free -m', False, 300),
    ('signed-media-verify', 'luma-platform verify /media/luma', True, 3600),
]


def observe(vm, name, command, timeout, folder):
    vm.counter += 1
    marker = f'__LUMA_OBS_{vm.counter}'
    started = time.monotonic()
    vm.send(command+f'; printf "\\n{marker}=%s__\\n" "$?"')
    result = vm.expect(rb'\r?\n'+marker.encode()+rb'=\d+__\r?\n', timeout)
    code = int(re.search(marker.encode()+rb'=(\d+)__', result).group(1))
    (folder/(name+'.txt')).write_bytes(result)
    return dict(exit_code=code, seconds=round(time.monotonic()-started, 1),
                transcript=f'observations/{name}.txt', transcript_sha256=hashlib.sha256(result).hexdigest())


def checked_paths(medium, media, work, artifacts=Path('/work/artifacts'), work_root=Path('/work')):
    """Admit only an exported medium and a new work directory; return resolved paths."""
    if medium not in MEDIA:
        raise SystemExit('unknown medium')
    media = Path(media).resolve(strict=True)
    work = Path(work).resolve()
    if not media.is_file() or not media.is_relative_to(artifacts) or media.suffix != SUFFIX[medium]:
        raise SystemExit(f'only the generated {SUFFIX[medium]} under {artifacts} is accepted for {medium}')
    if work.parent != work_root or not work.name.startswith('vm-') or work.exists():
        raise SystemExit(f'use a new {work_root}/vm-<run> directory')
    return media, media.parent/'secureboot.cer', work


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--medium', choices=MEDIA, required=True)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--media-sha256', required=True)
    parser.add_argument('--certificate-sha256', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=9000)
    args = parser.parse_args(argv)
    medium = args.medium
    media, certificate, work = checked_paths(medium, args.media, args.work)
    if not re.fullmatch('[0-9a-f]{64}', args.media_sha256) or not re.fullmatch('[0-9a-f]{64}', args.certificate_sha256):
        raise SystemExit('exact SHA-256 pins required')
    if file_sha256(certificate) != args.certificate_sha256:
        raise SystemExit('public Secure Boot certificate differs from its pin')
    print('Hashing the medium before boot', flush=True)
    if file_sha256(media) != args.media_sha256:
        raise SystemExit('medium differs from its verified pin before boot')
    checks = required_checks(medium)
    work.mkdir()
    folder = work/'observations'
    folder.mkdir()
    live = work/f'{medium}-live'
    record = dict(schema_version=1, purpose='luma-live-media-boot-smoke-v3', result='failed', medium=medium,
                  media=str(media), media_sha256=args.media_sha256, acceleration='tcg', uefi=True,
                  secure_boot_tested=True, secure_boot_certificate_sha256=args.certificate_sha256,
                  guest_memory_mib=MEMORY_MIB, network=False, attached_block_devices=[ATTACHED[medium]],
                  required_checks={}, observations={}, gated_checks={}, clean_shutdown=None,
                  ordering_cycle_in_boot_transcript=None,
                  installation_tested=False, graphical_session_tested=False,
                  physical_usb_drive_tested=False, physical_optical_drive_tested=False,
                  physical_hardware_tested=False, gate_closing=False, test_sources=TEST_SOURCES,
                  harness_sha256=file_sha256(Path(__file__)))
    vm = None
    try:
        vm = LiveMediaVM(medium, media, certificate, live, args.timeout, 'tcg')
        record['host_memory_admission'] = vm.host_memory_admission
        record['qemu_command'] = vm.command
        boot = vm.expect(rb'root@[^\r\n]*[#]', 2400)
        record['root_shell_reached'] = True
        record['ordering_cycle_in_boot_transcript'] = bool(CYCLE.search(boot))
        vm.run(NO_PAGER)
        for name, command in checks:
            print(f'Live {medium} check: {name}', flush=True)
            vm.run(command, timeout=600)
            record['required_checks'][name] = 'passed'
        for name, command, gated, timeout in OBSERVED:
            print(f'Live {medium} observation: {name}', flush=True)
            record['observations'][name] = observe(vm, name, command, timeout, folder)
            if gated:
                record['gated_checks'][name] = 'passed' if record['observations'][name]['exit_code'] == 0 else 'failed'
        try:
            poweroff(vm, True)
            record['clean_shutdown'] = 'passed'
        except RuntimeError as error:
            record['clean_shutdown'] = 'failed: '+str(error)
            raise
        vm.log.flush()
        record['ordering_cycle_in_serial_log'] = bool(CYCLE.search((live/'serial.log').read_bytes()))
        failed = sorted(name for name, value in record['gated_checks'].items() if value != 'passed')
        if record['ordering_cycle_in_boot_transcript']:
            failed.append('no-ordering-cycle-in-boot-transcript')
        if record['ordering_cycle_in_serial_log']:
            failed.append('no-ordering-cycle-in-serial-log')
        if failed:
            raise RuntimeError(f'gated live {medium} checks failed: '+', '.join(failed))
        record['result'] = 'passed'
    except BaseException as error:
        record['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if vm is not None:
            vm.close()
        serial = live/'serial.log'
        if serial.exists():
            record['ordering_cycle_in_serial_log'] = bool(CYCLE.search(serial.read_bytes()))
            record['serial_log_sha256'] = file_sha256(serial)
        record['media_sha256_after'] = file_sha256(media)
        record['media_unchanged'] = record['media_sha256_after'] == args.media_sha256
        if not record['media_unchanged']:
            record['result'] = 'failed'
        (work/'result.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
        print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
