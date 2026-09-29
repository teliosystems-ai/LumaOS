"""Immutable-root shutdown restore wiring, without touching host boot state."""
import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parents[1]/'image'
spec = importlib.util.spec_from_file_location('shutdown_policy', IMAGE/'shutdown_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


@unittest.skipUnless(os.name == 'posix', 'requires Linux symlinks')
class ShutdownRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='luma-shutdown-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in ('boot/luma-initrd', 'usr/lib/dracut/dracut-initramfs-restore',
                         'usr/lib/dracut/modules.d/98dracut-systemd/dracut-shutdown.service'):
            target = self.root/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'public fixture')

    def test_exact_idempotent_verified_root_alias_and_activation(self):
        for _ in range(2):
            policy.configure(self.root, '6.8.0-142-generic')
        self.assertEqual((self.root/'boot/initrd.img-6.8.0-142-generic').readlink(), Path('luma-initrd'))
        link = self.root/'etc/systemd/system/multi-user.target.wants/dracut-shutdown.service'
        self.assertEqual(link.readlink(), Path('/usr/lib/systemd/system/dracut-shutdown.service'))

    def test_missing_prerequisite_and_path_substitution_refused(self):
        for version in ('', '../escape', '6.8/escape'):
            with self.assertRaises(ValueError):
                policy.configure(self.root, version)
        initrd = self.root/'boot/luma-initrd'
        initrd.unlink()
        with self.assertRaises(ValueError):
            policy.configure(self.root, '6.8-test')
        initrd.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            policy.configure(self.root, '6.8-test')

    def test_existing_file_or_wrong_link_never_overwritten(self):
        alias = self.root/'boot/initrd.img-6.8-test'
        alias.write_bytes(b'preserve me')
        with self.assertRaises(ValueError):
            policy.configure(self.root, '6.8-test')
        self.assertEqual(alias.read_bytes(), b'preserve me')
        alias.unlink()
        alias.symlink_to('other-initrd')
        with self.assertRaises(ValueError):
            policy.configure(self.root, '6.8-test')
        self.assertEqual(alias.readlink(), Path('other-initrd'))


class ShutdownInitrdTests(unittest.TestCase):
    def test_required_teardown_inventory(self):
        paths = ['shutdown', 'usr/bin/umount', 'usr/sbin/dmsetup',
                 'usr/lib/dracut/hooks/shutdown/25-dm-shutdown.sh',
                 'usr/lib/luma-shutdown-check.sh',
                 'usr/lib/dracut/hooks/shutdown/90-luma-shutdown.sh']
        listing = '\n'.join('-rwx root root '+p for p in paths)
        with patch.object(policy.subprocess, 'check_output', return_value=listing):
            self.assertFalse(policy.verify_initrd(Path('/fixture'))['boot_tested'])
        for missing in paths:
            with self.subTest(missing=missing), patch.object(policy.subprocess, 'check_output',
                    return_value='\n'.join(p for p in paths if p != missing)):
                with self.assertRaises(ValueError):
                    policy.verify_initrd(Path('/fixture'))


@unittest.skipUnless(os.name == 'posix', 'requires Linux shell')
class ShutdownStorageTests(unittest.TestCase):
    def test_cleanup_marker_requires_unmounted_root_and_no_dm_devices(self):
        helper = IMAGE/'overlay/usr/lib/dracut/modules.d/91luma/luma-shutdown-check.sh'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            mounts = root/'mounts'
            devices = root/'block'
            devices.mkdir()
            def check(expected):
                result = subprocess.run(['/bin/sh', '-c',
                    '. "$1"; luma_shutdown_storage_check "$2" "$3"',
                    'fixture', str(helper), str(mounts), str(devices)])
                self.assertEqual(result.returncode, expected)
            check(1)  # Missing inventory cannot become a success.
            mounts.write_text('')
            check(1)
            mounts.write_text('proc /proc proc rw 0 0\n')
            check(0)
            for mounted in ('/oldroot', '/oldroot/var', '/oldroot/efi'):
                mounts.write_text('device '+mounted+' ext4 ro 0 0\n')
                check(1)
            mounts.write_text('proc /proc proc rw 0 0\n')
            (devices/'dm-0').mkdir()
            check(1)
            (devices/'dm-0').rmdir()
            (devices/'dm-1').symlink_to('missing')
            check(1)


if __name__ == '__main__':
    unittest.main()
