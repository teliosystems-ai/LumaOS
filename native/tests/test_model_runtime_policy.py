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
        activation = source.split('fn activate_cached(')[1].split('fn reconcile_downloads')[0]
        self.assertIn('runtime_lock(var, true)?', activation)
        self.assertLess(activation.index('runtime_lock('), activation.index('model-selection.json'))
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(serve.index('runtime_lock('), serve.index('selected()?'))
        self.assertIn('verified_file(&file, &p)?', serve)
        self.assertIn('"/proc/self/fd/{}"', serve)
        self.assertIn('inherit_runtime_files(&mut command, &verified, &runtime)', serve)
        self.assertNotIn('file.to_str()', serve)

    def test_pending_activation_fences_worker_and_reference_env_is_root_owned(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        provision = source.split('fn activate_cached(')[1].split('fn reconcile_downloads')[0]
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(provision.index('begin_activation(&state, p)?'),
                        provision.index('state.join(REFERENCE_ENV)'))
        self.assertLess(provision.index('begin_activation(&state, p)?'),
                        provision.index('model-selection.json'))
        self.assertLess(serve.index('activation_absent('), serve.index('selected()?'))
        self.assertIn('"0:990"', provision)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-reference.service').read_text()
        self.assertIn('EnvironmentFile=-/var/lib/luma-os/model-reference.env', unit)
        reference = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-reference').read_text()
        self.assertIn('/var/lib/luma-os/model-reference.env r,', reference)
        model = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('/var/lib/luma-os/model-activation.pending r,', model)
        self.assertIn('/sys/fs/cgroup/**/memory.max r,', model)
        self.assertIn('/sys/fs/cgroup/memory.max r,', model)

    def test_verified_acquisition_precedes_managed_worker_stop(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        prepare = source.split('fn prepare_model(')[1].split('fn activate_cached(')[0]
        activate = source.split('fn activate_cached(')[1].split('fn reconcile_downloads')[0]
        install = source.split('pub fn install(id: &str)')[1].split('pub fn unit()')[0]
        self.assertIn('fetch(&file, p)?', prepare)
        self.assertIn('check_cached(p, available_space(&models)?)?', prepare)
        self.assertIn('check(p, available_space(&models)?)?', prepare)
        self.assertNotIn('fetch(', activate)
        self.assertIn('verify_file(&models.join', activate)
        self.assertLess(install.index('prepare_model('),
                        install.index('"stop", "luma-model.service"'))
        self.assertLess(install.index('"stop", "luma-model.service"'),
                        install.index('activate_cached('))
        restore = source.split('fn restore_prior(')[1].split('fn begin_activation(')[0]
        self.assertLess(restore.index('activation_absent('),
                        restore.index('"restart", "luma-model.service"'))
        self.assertLess(restore.index('verify_file('),
                        restore.index('"restart", "luma-model.service"'))

    def test_legacy_migration_is_explicit_and_validates_before_service_stop(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        migration = source.split('pub fn migrate_legacy()')[1].split('/// Read-only')[0]
        self.assertLess(migration.index('legacy_configuration_at('),
                        migration.index('"stop", "luma-model.service"'))
        self.assertLess(migration.index('verify_file('),
                        migration.index('"stop", "luma-model.service"'))
        self.assertLess(migration.index('migrate_legacy_at('),
                        migration.index('"restart", "luma-model.service"'))
        self.assertLess(migration.index('"reset-failed", "luma-model.service"'),
                        migration.index('"restart", "luma-model.service"'))
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("model-migrate-legacy") if args.len() == 1', main)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-reference.service').read_text()
        self.assertNotIn('EnvironmentFile=-/var/lib/luma-os/reference/model.env', unit)


if __name__ == '__main__':
    unittest.main()
