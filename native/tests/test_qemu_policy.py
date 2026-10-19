"""Real disposable image-file policy tests, never service/sysfs execution."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('luma_qemu_policy_tests', ROOT/'native/image/qemu_policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class QemuPolicyTests(unittest.TestCase):
    def setUp(self):
        storage = Path(os.environ['LUMA_STORAGE_TEST_ROOT']).resolve(strict=True)
        temporary = tempfile.TemporaryDirectory(prefix='qemu-policy-', dir=storage)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in (policy.CONFIG_PATH, policy.VENDOR_PATH, policy.MASK_PATH,
                         policy.WANTED_PATH, policy.BINARY_PATH):
            (self.root/relative).parent.mkdir(parents=True, exist_ok=True)
        self.vendor = self.root/policy.VENDOR_PATH
        self.vendor.write_bytes(policy.VENDOR_UNIT)
        self.vendor.chmod(0o644)
        self.binary = self.root/policy.BINARY_PATH
        # A genuine ELF fixture, not a claim that /usr/bin/true is QEMU.
        shutil.copyfile('/usr/bin/true', self.binary)
        self.binary.chmod(0o755)
        self.config = self.root/policy.CONFIG_PATH
        self.config.write_bytes(policy.PACKAGED_CONFIG)
        self.config.chmod(0o644)
        self.wanted = self.root/policy.WANTED_PATH
        self.wanted.symlink_to(policy.VENDOR_TARGET)
        self.mask = self.root/policy.MASK_PATH

    def assert_unchanged(self):
        self.assertEqual(self.config.read_bytes(), policy.PACKAGED_CONFIG)
        self.assertEqual(str(self.wanted.readlink()), policy.VENDOR_TARGET)

    def test_packaged_configuration_becomes_exact_masked_state_and_is_idempotent(self):
        before = self.binary.read_bytes(), self.vendor.read_bytes()
        report = policy.configure(self.root)
        self.assertEqual(self.config.read_bytes(), policy.CONFIG)
        self.assertEqual(self.config.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(str(self.mask.readlink()), '/dev/null')
        self.assertFalse(self.wanted.exists())
        self.assertEqual(policy.configure(self.root), report)
        self.assertEqual(policy.validate(self.root), report)
        self.assertEqual(before, (self.binary.read_bytes(), self.vendor.read_bytes()))
        self.assertFalse(report['service_executed'])
        self.assertFalse(report['kernel_ksm_state_observed'])
        self.assertFalse(report['kvm_or_native_boot_qualified'])

    def test_absent_defaults_and_wanted_link_are_supported_without_changing_modes(self):
        self.config.unlink()
        self.wanted.unlink()
        previous = os.umask(0o077)
        try:
            policy.configure(self.root)
        finally:
            os.umask(previous)
        self.assertEqual(self.config.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(self.config.read_bytes(), policy.CONFIG)

    def test_host_root_and_noncanonical_root_refuse(self):
        with self.assertRaises(ValueError):
            policy.configure(Path('/'))
        alias = self.root/'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            policy.configure(alias)
        self.assert_unchanged()

    def test_unexpected_wanted_regular_or_alias_refuses_before_mutation(self):
        self.wanted.unlink()
        self.wanted.write_text('preserve foreign unit')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assertEqual(self.wanted.read_text(), 'preserve foreign unit')
        self.assertEqual(self.config.read_bytes(), policy.PACKAGED_CONFIG)
        self.wanted.unlink()
        for target in ('/dev/null', '/tmp/foreign.service', '../qemu-kvm.service'):
            self.wanted.symlink_to(target)
            with self.assertRaises(ValueError):
                policy.configure(self.root)
            self.assertEqual(str(self.wanted.readlink()), target)
            self.wanted.unlink()

    def test_unexpected_mask_regular_or_alias_refuses_before_mutation(self):
        self.mask.write_text('preserve overridden unit')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assertEqual(self.mask.read_text(), 'preserve overridden unit')
        self.assert_unchanged()
        self.mask.unlink()
        self.mask.symlink_to('/usr/lib/systemd/system/qemu-kvm.service')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assert_unchanged()

    def test_defaults_alias_hardlink_or_unknown_content_never_gets_overwritten(self):
        self.config.unlink()
        self.config.symlink_to(self.vendor)
        with self.assertRaises(OSError):
            policy.configure(self.root)
        self.assertEqual(self.vendor.read_bytes(), policy.VENDOR_UNIT)
        self.config.unlink()
        os.link(self.vendor, self.config)
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.config.unlink()
        self.config.write_bytes(b'KSM_ENABLED=1\n')
        self.config.chmod(0o644)
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assertEqual(self.config.read_bytes(), b'KSM_ENABLED=1\n')
        self.assertEqual(str(self.wanted.readlink()), policy.VENDOR_TARGET)

    def test_changed_vendor_binary_parent_or_retained_stage_refuses(self):
        self.vendor.write_bytes(policy.VENDOR_UNIT+b'# unexpected\n')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assert_unchanged()
        self.vendor.write_bytes(policy.VENDOR_UNIT)
        original = self.binary.read_bytes()
        self.binary.write_bytes(b'not ELF')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.binary.write_bytes(original)
        self.config.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.config.parent.chmod(0o755)
        stage = self.root/policy.STAGING_PATH
        stage.write_bytes(b'retained interrupted image policy')
        with self.assertRaises(ValueError):
            policy.configure(self.root)
        self.assertEqual(stage.read_bytes(), b'retained interrupted image policy')
        self.assert_unchanged()

    def test_validation_refuses_reenabled_autostart_or_mode_and_configuration_drift(self):
        policy.configure(self.root)
        self.wanted.symlink_to(policy.VENDOR_TARGET)
        with self.assertRaises(ValueError):
            policy.validate(self.root)
        self.wanted.unlink()
        self.config.chmod(0o666)
        with self.assertRaises(ValueError):
            policy.validate(self.root)
        self.config.chmod(0o644)
        self.config.write_bytes(policy.PACKAGED_CONFIG)
        with self.assertRaises(ValueError):
            policy.validate(self.root)


if __name__ == '__main__':
    unittest.main()
