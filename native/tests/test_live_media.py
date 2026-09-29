"""Boot-mode dependency regression for slow/missing live installation media."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

IMAGE = Path(__file__).resolve().parents[1]/'image'
OVERLAY = IMAGE/'overlay'
GENERATOR = OVERLAY/'usr/lib/systemd/system-generators/luma-boot-generator'
UNITS = OVERLAY/'etc/systemd/system'


class LiveMediaContractTests(unittest.TestCase):
    def test_no_unconditional_payload_device_in_fstab(self):
        source = (IMAGE/'assemble.py').read_text()
        fstab = source.split("put('etc/fstab',", 1)[1].split("put('etc/systemd/", 1)[0]
        self.assertNotIn('luma-payload', fstab)

    def test_mount_is_readonly_and_console_survives_failure(self):
        mount = (UNITS/'media-luma.mount').read_text()
        for required in ('ConditionKernelCommandLine=luma.mode=live',
                         'What=/dev/disk/by-partlabel/luma-payload',
                         'Where=/media/luma', 'Options=ro,nodev,nosuid,noexec',
                         'TimeoutSec=90'):
            self.assertIn(required, mount)
        for name in ('luma-live-console.service', 'luma-live-vt.service'):
            unit = (UNITS/name).read_text()
            self.assertIn('After=systemd-user-sessions.service media-luma.mount', unit)
            self.assertNotIn('Requires=media-luma.mount', unit)


@unittest.skipUnless(os.name == 'posix', 'requires Linux shell and symlinks')
class LiveMediaGeneratorTests(unittest.TestCase):
    def test_mode_specific_dependencies_and_bounded_device_wait(self):
        for mode in ('live', 'installed', 'unknown'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary = root/'bin'
                binary.mkdir()
                fake_cat = binary/'cat'
                fake_cat.write_text('#!/bin/sh\ncase "$1" in\n'
                                    '/proc/cmdline) printf "luma.mode=%s\\n" "$TEST_MODE" ;;\n'
                                    '/sys/class/tty/console/active) printf "tty0 ttyS0\\n" ;;\n'
                                    '*) exit 1 ;;\nesac\n')
                fake_cat.chmod(0o755)
                output = root/'generated'
                output.mkdir()
                env = {**os.environ, 'TEST_MODE':mode, 'PATH':str(binary)+':'+os.environ['PATH']}
                subprocess.run(['/bin/sh', str(GENERATOR), str(output)], env=env, check=True)
                media = output/'local-fs.target.wants/media-luma.mount'
                timeout = output/r'dev-disk-by\x2dpartlabel-luma\x2dpayload.device.d/timeout.conf'
                self.assertEqual(media.is_symlink(), mode == 'live')
                self.assertEqual(timeout.exists(), mode == 'live')
                if mode == 'live':
                    self.assertEqual(os.readlink(media), '/etc/systemd/system/media-luma.mount')
                    self.assertEqual(timeout.read_text(), '[Unit]\nJobRunningTimeoutSec=90s\n')
                    for name in ('luma-live-console.service', 'luma-live-vt.service'):
                        self.assertTrue((output/'multi-user.target.wants'/name).is_symlink())
                self.assertEqual((output/'local-fs.target.wants/efi.mount').is_symlink(), mode == 'installed')


if __name__ == '__main__':
    unittest.main()
