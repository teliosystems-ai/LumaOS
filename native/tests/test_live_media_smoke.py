import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))

import live_media_smoke as smoke  # noqa: E402

SEQUENCE19 = Path(__file__).resolve().parents[1] / 'evidence' / 'candidate19_optical_smoke_2026_10_28.py'


def load_sequence19():
    spec = importlib.util.spec_from_file_location('candidate19_optical_smoke_reference', SEQUENCE19)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommandTests(unittest.TestCase):
    def test_optical_command_is_the_sequence19_command(self):
        iso, variables, sockets = '/work/artifacts/x.iso', '/work/vm-a/firmware.fd', '/tmp/luma-vm-x'
        expected = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', '8192', '-smp', '2', '-cpu', 'max',
                    '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}',
                    '-drive', f'if=none,id=optical,media=cdrom,readonly=on,format=raw,file={iso}',
                    '-device', 'ide-cd,drive=optical,bus=ide.0,bootindex=1',
                    '-nic', 'none', '-display', 'none', '-monitor', 'none',
                    '-serial', f'unix:{sockets}/console.sock,server=on,wait=off',
                    '-qmp', f'unix:{sockets}/qmp.sock,server=on,wait=off', '-no-reboot']
        self.assertEqual(smoke.qemu_command('optical', iso, variables, sockets), expected)

    def test_every_medium_is_one_read_only_boot_device_under_secure_boot_firmware(self):
        for medium in smoke.MEDIA:
            with self.subTest(medium=medium):
                command = smoke.qemu_command(medium, '/work/artifacts/m', '/work/vm-a/firmware.fd', '/tmp/s')
                joined = ' '.join(command)
                self.assertEqual(joined.count('bootindex='), 1)
                self.assertEqual(joined.count('file=/work/artifacts/m'), 1)
                drives = [command[index + 1] for index, value in enumerate(command) if value == '-drive']
                media = [drive for drive in drives if not drive.startswith('if=pflash')]
                self.assertEqual(len(media), 1)
                self.assertIn('readonly=on', media[0])
                self.assertIn('file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd', joined)
                self.assertIn('accel=tcg', joined)
                self.assertNotIn('kvm', joined)
                self.assertIn('-nic none', joined)

    def test_disk_media_run_without_the_default_optical_drive(self):
        # Without -nodefaults, q35 attached an empty DVD drive that the usb-disk
        # block-device check of sequence-20 attempt a found as sr0.
        self.assertNotIn('-nodefaults', smoke.qemu_command('optical', '/work/artifacts/m', '/work/vm-a/f', '/tmp/s'))
        for medium in ('virtio-disk', 'usb-disk'):
            with self.subTest(medium=medium):
                command = smoke.qemu_command(medium, '/work/artifacts/m', '/work/vm-a/firmware.fd', '/tmp/s')
                self.assertEqual(command.count('-nodefaults'), 1)
                self.assertEqual(command[command.index('-vga') + 1], 'std')
                for optical in ('cdrom', 'ide-cd', 'scsi-cd', '-cdrom'):
                    self.assertNotIn(optical, ' '.join(command))
                without = [value for value in command if value not in smoke.NO_DEFAULT_OPTICAL]
                self.assertEqual(without, ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', '8192', '-smp', '2',
                                           '-cpu', 'max',
                                           '-drive', f'if=pflash,format=raw,readonly=on,file={smoke.FIRMWARE}',
                                           '-drive', 'if=pflash,format=raw,file=/work/vm-a/firmware.fd',
                                           *smoke.media_arguments(medium, '/work/artifacts/m'),
                                           '-nic', 'none', '-display', 'none', '-monitor', 'none',
                                           '-serial', 'unix:/tmp/s/console.sock,server=on,wait=off',
                                           '-qmp', 'unix:/tmp/s/qmp.sock,server=on,wait=off', '-no-reboot'])

    def test_disk_media_attach_as_a_virtio_disk_or_a_removable_usb_stick(self):
        self.assertEqual(smoke.media_arguments('virtio-disk', '/work/artifacts/a.img'),
                         ['-drive', 'if=none,id=media,format=raw,readonly=on,file=/work/artifacts/a.img',
                          '-device', 'virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex=1'])
        usb = smoke.media_arguments('usb-disk', '/work/artifacts/a.img')
        self.assertEqual(usb[:2], ['-device', 'qemu-xhci,id=xhci'])
        self.assertIn('usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=1', usb)
        with self.assertRaises(ValueError):
            smoke.media_arguments('floppy', '/work/artifacts/a.img')


class CheckTests(unittest.TestCase):
    def test_ten_required_checks_and_five_gated_observations_per_medium(self):
        for medium in smoke.MEDIA:
            with self.subTest(medium=medium):
                names = [name for name, _ in smoke.required_checks(medium)]
                self.assertEqual(len(names), 10)
                self.assertEqual(len(set(names)), 10)
                self.assertEqual(names[4:], [name for name, _ in smoke.COMMON_CHECKS])
        self.assertEqual(len(smoke.OBSERVED), 13)
        self.assertEqual([name for name, _, gated, _ in smoke.OBSERVED if gated],
                         ['no-failed-units', 'recovery-keeper-active', 'recovery-producer-path-active',
                          'no-ordering-cycle-in-journal', 'signed-media-verify'])

    def test_disk_checks_assume_no_optical_device(self):
        for medium, disk in (('virtio-disk', 'vda'), ('usb-disk', 'sda')):
            with self.subTest(medium=medium):
                text = '\n'.join(command for _, command in smoke.disk_checks(medium))
                for optical in ('sr0', 'iso9660', 'luma.media=optical', 'cdrom'):
                    self.assertNotIn(optical, text)
                self.assertIn(f'/sys/class/block/{disk}/ro)" = 1', text)
                self.assertIn('by-partlabel/luma-payload', text)
                self.assertIn("! grep -q 'luma[.]media=' /proc/cmdline", text)
                other = 'sda' if disk == 'vda' else 'vda'
                self.assertNotIn(other, text)
        self.assertIn('removable)" = 1', smoke.disk_checks('usb-disk')[1][1])
        self.assertIn('grep -q /virtio', smoke.disk_checks('virtio-disk')[1][1])

    def test_ordering_cycle_patterns_never_match_their_own_echo(self):
        for _, command, _, _ in smoke.OBSERVED:
            self.assertIsNone(smoke.CYCLE.search(command.encode()))
        for medium in smoke.MEDIA:
            for _, command in smoke.required_checks(medium):
                self.assertIsNone(smoke.CYCLE.search(command.encode()))

    @unittest.skipUnless(shutil.which('bash'), 'bash is not installed')
    def test_guest_commands_are_valid_shell(self):
        commands = [smoke.NO_PAGER] + [command for _, command, _, _ in smoke.OBSERVED]
        for medium in smoke.MEDIA:
            commands += [command for _, command in smoke.required_checks(medium)]
        for command in commands:
            with self.subTest(command=command[:60]):
                subprocess.run(['bash', '-n', '-c', command], check=True)

    @unittest.skipUnless(SEQUENCE19.is_file(), 'native/evidence is not part of this source cut')
    def test_optical_run_keeps_the_executed_sequence19_checks(self):
        reference = load_sequence19()
        self.assertEqual(smoke.required_checks('optical'), reference.REQUIRED)
        self.assertEqual(smoke.OBSERVED, reference.OBSERVED)
        self.assertEqual((smoke.NO_PAGER, smoke.MEMORY_MIB, smoke.OWNER, smoke.CYCLE.pattern),
                         (reference.NO_PAGER, reference.MEMORY_MIB, reference.OWNER, reference.CYCLE.pattern))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.artifacts = self.root / 'artifacts'
        self.artifacts.mkdir()
        for name in ('a.iso', 'a.img'):
            (self.artifacts / name).write_bytes(b'x')

    def check(self, medium, media, work='vm-run'):
        return smoke.checked_paths(medium, self.artifacts / media if isinstance(media, str) else media,
                                   self.root / work, self.artifacts, self.root)

    def test_admits_each_medium_with_its_suffix(self):
        for medium, name in (('optical', 'a.iso'), ('virtio-disk', 'a.img'), ('usb-disk', 'a.img')):
            media, certificate, work = self.check(medium, name)
            self.assertEqual((media, certificate, work),
                             (self.artifacts / name, self.artifacts / 'secureboot.cer', self.root / 'vm-run'))

    def test_refuses_another_suffix_location_or_work_directory(self):
        outside = self.root / 'a.img'
        outside.write_bytes(b'x')
        cases = [('optical', 'a.img', 'vm-run'), ('usb-disk', 'a.iso', 'vm-run'), ('virtio-disk', outside, 'vm-run'),
                 ('usb-disk', 'a.img', 'run'), ('usb-disk', 'a.img', 'artifacts'), ('cd', 'a.iso', 'vm-run')]
        for medium, media, work in cases:
            with self.subTest(medium=medium, media=str(media), work=work), self.assertRaises(SystemExit):
                self.check(medium, media, work)
        (self.root / 'vm-run').mkdir()
        with self.assertRaises(SystemExit):
            self.check('usb-disk', 'a.img')

    @unittest.skipUnless(os.name == 'posix', 'the VM fixture needs a POSIX host')
    def test_refuses_acceleration_before_creating_anything(self):
        work = self.root / 'vm-run' / 'usb-disk-live'
        with self.assertRaisesRegex(ValueError, 'software emulation'):
            smoke.LiveMediaVM('usb-disk', self.artifacts / 'a.img', self.artifacts / 'secureboot.cer', work, 1, 'kvm')
        self.assertFalse((self.root / 'vm-run').exists())


if __name__ == '__main__':
    unittest.main()
