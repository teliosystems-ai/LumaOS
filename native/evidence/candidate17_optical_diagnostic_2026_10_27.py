#!/usr/bin/env python3
"""Sequence-17 optical discovery diagnostic: fixed initrd script, not image evidence.

Diagnostic-only harness. It direct-boots the sequence-17 kernel with the
sequence-17 initrd plus one appended cpio that replaces only
/usr/lib/luma-optical.sh with the pinned fixed script and adds a tracing
drop-in. The unchanged sequence-17 ISO is the only block device (read-only
AHCI CD). The UKI is bypassed, so Secure Boot is NOT tested and nothing here is
signed-image, release or qualification evidence; a rebuilt sequence must still
pass the signed optical smoke.
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

MEMORY_MIB = 4096
# Exact sequence-17 UKI command line, as printed by the signed optical boot.
COMMAND_LINE = ('root=/dev/mapper/root ro roothash=e02c9495eb837a4f65823c32415e43f69aee49659677183c68c91ee4c5b3329f '
                'systemd.verity_root_options=panic-on-corruption systemd.verity_root_data=/dev/luma-optical-root '
                'systemd.verity_root_hash=/dev/luma-optical-hash luma.mode=live luma.slot=live luma.media=optical '
                'systemd.unit=multi-user.target console=tty0 console=ttyS0,115200n8 apparmor=1 security=apparmor '
                'systemd.show_status=yes rd.shell=0 panic=10')
DROP_IN = b'''[Service]
ExecStartPre=-/bin/sh -c 'echo "LUMA_DIAG_SR0_RO_BEFORE=$$(cat /sys/class/block/sr0/ro)"'
ExecStart=
ExecStart=/bin/sh -x /lib/luma-optical.sh
ExecStartPost=-/bin/sh -c 'echo "LUMA_DIAG_SR0_RO_AFTER=$$(cat /sys/class/block/sr0/ro)"'
StandardOutput=journal+console
StandardError=journal+console
'''


def file_sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def newc(entries):
    """Uncompressed newc archive: (path, mode, data or None for a directory)."""
    out = bytearray()

    def member(number, name, mode, data):
        nonlocal out
        name = name.encode()+b'\0'
        fields = [number, mode, 0, 0, 1 if mode & 0o170000 != 0o040000 else 2, 0, len(data), 0, 0, 0, 0,
                  len(name), 0]
        out += b'070701'+b''.join(b'%08X' % field for field in fields)+name
        out += b'\0'*(-len(out) % 4)+data
        out += b'\0'*(-len(out) % 4)
    for number, (name, mode, data) in enumerate(entries, 1):
        member(number, name, (0o040000 if data is None else 0o100000) | mode, data or b'')
    member(0, 'TRAILER!!!', 0, b'')
    return bytes(out)


class DiagnosticVM(VM):
    """VM fixture methods with direct kernel boot and an optical-only inventory."""

    def __init__(self, kernel: Path, initrd: Path, iso: Path, work: Path, timeout: int):
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
        self.secure_boot = False
        self.acceleration = 'tcg'
        self.memory_mib = MEMORY_MIB
        command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', str(MEMORY_MIB), '-smp', '2',
                   '-cpu', 'max',
                   '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                   '-drive', f'if=pflash,format=raw,file={variables}',
                   '-kernel', str(kernel), '-initrd', str(initrd), '-append', COMMAND_LINE,
                   '-drive', f'if=none,id=optical,media=cdrom,readonly=on,format=raw,file={iso}',
                   '-device', 'ide-cd,drive=optical,bus=ide.0',
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
    # The discovery unit exists only in the initrd; its read-only loops survive switch-root.
    ('fixed-discovery-loops',
     'losetup --list --noheadings --output RO,BACK-FILE | grep -Eqx " *1 +/run/initramfs/luma-optical/root\\.ext4" '
     '&& losetup --list --noheadings --output RO,BACK-FILE | grep -Eqx " *1 +/run/initramfs/luma-optical/root\\.verity"'),
    ('only-optical-loop-and-dm-block-devices',
     'test -z "$(ls /sys/class/block | grep -Ev \'^(loop[0-9]+|sr0|dm-[0-9]+|zram[0-9]+)$\')" '
     '&& test "$(cat /sys/class/block/sr0/device/type)" = 5 && test "$(cat /sys/class/block/sr0/ro)" = 1'),
    ('verity-root', 'test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root'),
    ('optical-media-bind-mount',
     'systemctl is-active media-luma.mount && test "$(findmnt -n -o FSTYPE /media/luma)" = iso9660 '
     '&& test -s /media/luma/release.json && test -s /media/luma/release.sig'),
    ('broker-and-reference-active', 'systemctl is-active luma-broker.service luma-reference.service'),
]

OBSERVED = [
    ('loop-inventory', 'losetup --list --noheadings --output NAME,RO,BACK-FILE'),
    ('verity-status', 'veritysetup status root'),
    ('media-mount', 'findmnt -n -o SOURCE,FSTYPE,OPTIONS /media/luma'),
    ('signed-media-verify', 'luma-platform verify /media/luma'),
    ('failed-units', 'systemctl --failed --no-legend --plain'),
    ('discovery-journal', 'journalctl -b -o cat --no-pager -u luma-optical.service | tail -n 80'),
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
    parser.add_argument('--kernel-sha256', required=True)
    parser.add_argument('--initrd-sha256', required=True)
    parser.add_argument('--fixed-script', type=Path, required=True)
    parser.add_argument('--fixed-script-sha256', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=3600)
    args = parser.parse_args()
    iso = args.iso.resolve(strict=True)
    kernel = Path('/work/root/boot/vmlinuz-6.8.0-142-generic')
    initrd = Path('/work/root/boot/luma-initrd')
    work = args.work.resolve()
    if not iso.is_file() or not iso.is_relative_to('/work/artifacts') or iso.suffix != '.iso':
        raise SystemExit('only the generated ISO under /work/artifacts is accepted')
    if work.parent != Path('/work') or not work.name.startswith('vm-') or work.exists():
        raise SystemExit('use a new /work/vm-<run> directory')
    pins = [args.iso_sha256, args.kernel_sha256, args.initrd_sha256, args.fixed_script_sha256]
    if not all(re.fullmatch('[0-9a-f]{64}', pin) for pin in pins):
        raise SystemExit('exact SHA-256 pins required')
    script = args.fixed_script.read_bytes()
    for path, data, pin in ((kernel, None, args.kernel_sha256), (initrd, None, args.initrd_sha256),
                            (args.fixed_script, script, args.fixed_script_sha256)):
        actual = hashlib.sha256(data).hexdigest() if data is not None else file_sha256(path)
        if actual != pin:
            raise SystemExit(f'{path} differs from its pin')
    print('Hashing ISO before boot', flush=True)
    if file_sha256(iso) != args.iso_sha256:
        raise SystemExit('ISO differs from its verified pin before boot')
    work.mkdir()
    overlay = newc([('etc', 0o755, None), ('etc/systemd', 0o755, None), ('etc/systemd/system', 0o755, None),
                    ('etc/systemd/system/luma-optical.service.d', 0o755, None),
                    ('etc/systemd/system/luma-optical.service.d/90-diagnostic.conf', 0o644, DROP_IN),
                    ('usr/lib/luma-optical.sh', 0o755, script)])
    with tempfile.TemporaryDirectory(prefix='luma-overlay-', dir='/tmp') as unpacked:
        subprocess.run(['cpio', '-id', '--no-absolute-filenames', '--quiet'], input=overlay, cwd=unpacked,
                       check=True)
        if (Path(unpacked)/'usr/lib/luma-optical.sh').read_bytes() != script or \
                (Path(unpacked)/'etc/systemd/system/luma-optical.service.d/90-diagnostic.conf').read_bytes() != DROP_IN:
            raise SystemExit('overlay archive does not round-trip through cpio')
    combined = work/'diagnostic-initrd.img'
    base = initrd.read_bytes()
    combined.write_bytes(base+b'\0'*(-len(base) % 512)+overlay)
    record = dict(schema_version=1, purpose='luma-optical-discovery-diagnostic-v1', result='failed',
                  diagnostic_only=True, image_evidence=False, secure_boot_tested=False, uki_tested=False,
                  iso=str(iso), iso_sha256=args.iso_sha256, kernel_sha256=args.kernel_sha256,
                  initrd_sha256=args.initrd_sha256, fixed_script_sha256=args.fixed_script_sha256,
                  overlay_sha256=hashlib.sha256(overlay).hexdigest(),
                  combined_initrd_sha256=file_sha256(combined), drop_in_sha256=hashlib.sha256(DROP_IN).hexdigest(),
                  command_line=COMMAND_LINE, acceleration='tcg', uefi=True, guest_memory_mib=MEMORY_MIB,
                  network=False, attached_block_devices=['read-only AHCI CD carrying the ISO'],
                  required_checks={}, observations={}, diagnostic_markers=[], clean_shutdown=None,
                  installation_tested=False, graphical_session_tested=False, physical_hardware_tested=False,
                  gate_closing=False, test_sources=TEST_SOURCES, harness_sha256=file_sha256(Path(__file__)))
    vm = None
    try:
        vm = DiagnosticVM(kernel, combined, iso, work/'optical-diagnostic', args.timeout)
        record['host_memory_admission'] = vm.host_memory_admission
        record['qemu_command'] = vm.command
        boot = vm.expect(rb'root@[^\r\n]*[#]', 1800)
        record['diagnostic_markers'] = sorted({line.decode() for line in
                                               re.findall(rb'LUMA_DIAG_SR0_RO_(?:BEFORE|AFTER)=\d', boot)})
        record['root_shell_reached'] = True
        for name, command in REQUIRED:
            print('Diagnostic check: '+name, flush=True)
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
