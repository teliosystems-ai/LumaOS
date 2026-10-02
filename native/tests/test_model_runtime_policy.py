"""Model descriptor/lock wiring checks; not installed AppArmor qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ModelRuntimePolicyTests(unittest.TestCase):
    def test_apparmor_allows_only_read_and_lock_for_runtime_inode(self):
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('  /var/lib/luma-os/model-runtime.lock rk,', profile.splitlines())
        self.assertIn('  owner /proc/@{pid}/** r,', profile.splitlines())

    def test_activation_and_worker_share_lock_and_keep_verified_descriptor(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        provision = source.split('fn provision_locked(')[1].split('fn reconcile_downloads')[0]
        self.assertIn('runtime_lock(var, true)?', provision)
        self.assertLess(provision.index('runtime_lock('), provision.index('model-selection.json'))
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(serve.index('runtime_lock('), serve.index('selected()?'))
        self.assertIn('verified_file(&file, &p)?', serve)
        self.assertIn('"/proc/self/fd/{}"', serve)
        self.assertIn('inherit_runtime_files(&mut command, &verified, &runtime)', serve)
        self.assertNotIn('file.to_str()', serve)


if __name__ == '__main__':
    unittest.main()
