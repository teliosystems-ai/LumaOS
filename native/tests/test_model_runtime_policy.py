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

    def test_reviewed_partial_completion_verifies_weights_before_writing(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        complete = source.split('fn reviewed_complete_candidate(')[1].split('pub fn activation_reconcile(')[0]
        self.assertLess(complete.index('verify_file('),
                        complete.index('write_candidate_config('))
        self.assertLess(complete.index('write_candidate_config('),
                        complete.index('finish_activation('))
        reconcile = source.split('pub fn activation_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        self.assertIn('"--complete-candidate"', reconcile)
        self.assertNotIn('systemctl', reconcile)

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

    def test_installed_reconfiguration_checks_listener_after_restart(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        install = source.split('pub fn install(id: &str)')[1].split('pub fn unit()')[0]
        self.assertLess(install.index('"restart", "luma-model.service"'),
                        install.index('model-health.py'))
        self.assertLess(install.index('model-health.py'), install.rindex('running_prior('))
        self.assertIn('luma-reference.service', install)
        helper = (ROOT / 'native/image/overlay/usr/libexec/luma-os/model-health.py').read_text()
        self.assertIn("URL = 'http://127.0.0.1:8081/health'", helper)
        self.assertIn('urllib.request.ProxyHandler({})', helper)
        self.assertIn('NoRedirect()', helper)
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS + 1)', helper)

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

    def test_prior_backup_is_bound_private_and_worker_is_fenced_by_orphans(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        begin = source.split('fn begin_activation(')[1].split('struct ActivationObservation')[0]
        self.assertLess(begin.index('state.join(PRIOR_BACKUP)'), begin.index('state.join(ACTIVATION)'))
        self.assertIn('.mode(0o600)', begin)
        absent = source.split('fn activation_absent(')[1].split('fn checked_activation_bytes(')[0]
        self.assertIn('[ACTIVATION, PRIOR_BACKUP]', absent)
        backup = source.split('fn prior_backup_bytes(')[1].split('fn decode_prior_backup(')[0]
        self.assertIn('0o077', backup)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('/var/lib/luma-os/model-activation.prior r,', profile)

    def test_reviewed_restore_verifies_prior_before_writes_and_never_restarts(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        restore = source.split('fn reviewed_restore_configuration(')[1].split('fn observe_orphan_backup(')[0]
        self.assertLess(restore.index('verify_file('), restore.index('write_prior_configuration('))
        self.assertLess(restore.index('write_prior_configuration('), restore.index('clear_activation('))
        self.assertIn('current.review != observed.review', restore)
        self.assertNotIn('systemctl', restore)
        reconcile = source.split('pub fn activation_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for flag in ('--restore-prior', '--discard-orphan-backup'):
            self.assertIn(flag, reconcile)
        for forbidden in ('"key":', '"environment":', '"backup":', 'systemctl'):
            self.assertNotIn(forbidden, reconcile)

    def test_completed_rollback_is_retained_before_clearance_and_root_locked(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        finish = source.split('fn finish_activation(')[1].split('fn reviewed_clear_activation(')[0]
        self.assertLess(finish.index('retain_completed_prior('), finish.index('clear_activation('))
        reconcile = source.split('pub fn rollback_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for check in ('require_root()?', 'require_installed()?', 'operation_lock(var)?',
                      'runtime_lock(var, false)?', '"--restore-prior"'):
            self.assertIn(check, reconcile)
        for forbidden in ('"key":', '"environment":', '"prior":', 'systemctl'):
            self.assertNotIn(forbidden, reconcile)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertNotIn('/var/lib/luma-os/model-rollback', profile)

    def test_completed_rollback_fences_writes_and_consumes_before_clearance(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        restore = source.split('fn reviewed_completed_rollback(')[1].split('pub fn rollback_reconcile(')[0]
        self.assertLess(restore.index('observe_rollback('), restore.index('begin_activation_records('))
        self.assertLess(restore.index('begin_activation_records('), restore.index('write_prior_configuration('))
        self.assertLess(restore.index('write_prior_configuration('), restore.index('verify_file('))
        self.assertLess(restore.index('fs::remove_file(state.join(ROLLBACK))'),
                        restore.index('clear_activation('))
        for forbidden in ('systemctl', 'fetch(', 'remove_dir'):
            self.assertNotIn(forbidden, restore)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("model-rollback-reconcile") if args.len() == 1', main)

    def test_observed_restart_failure_is_fenced_before_managed_worker_stop(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        finish = source.split('fn finish_reconfiguration(')[1].split('struct Quarantine')[0]
        self.assertLess(finish.index('fence(failure.stage)'), finish.index('stop()'))
        install = source.split('pub fn install(id: &str)')[1].split('pub fn unit()')[0]
        self.assertIn('finish_reconfiguration(', install)
        self.assertIn('checked_restart_steps(', install)
        self.assertIn('publish_quarantine(', install)
        self.assertIn('"stop", "luma-model.service"', install)
        self.assertNotIn('reviewed_clear_quarantine(', install)

    def test_quarantine_fences_worker_and_normal_activation_but_not_reviewed_rollback(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        absent = source.split('fn activation_absent(')[1].split('fn checked_activation_bytes(')[0]
        self.assertIn('state.join(QUARANTINE)', absent)
        begin = source.split('fn begin_activation(')[1].split('fn begin_activation_records(')[0]
        self.assertIn('activation_absent(state)?', begin)
        rollback = source.split('fn reviewed_completed_rollback(')[1].split('pub fn rollback_reconcile(')[0]
        self.assertIn('begin_activation_records(', rollback)
        self.assertNotIn('remove_file(state.join(QUARANTINE))', rollback)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        self.assertIn('ConditionPathExists=!/var/lib/luma-os/model-quarantine.json', unit)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('/var/lib/luma-os/model-quarantine.json r,', profile)

    def test_quarantine_clearance_is_explicit_root_locked_and_non_starting(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        reconcile = source.split('pub fn quarantine_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for check in ('require_root()?', 'require_installed()?', 'operation_lock(var)?',
                      'runtime_lock(var, false)?', '"--clear-consistent"'):
            self.assertIn(check, reconcile)
        for forbidden in ('"key":', '"environment":', 'systemctl', 'model-disabled'):
            self.assertNotIn(forbidden, reconcile)
        publish = source.split('fn publish_quarantine(')[1].split('fn quarantine_bytes(')[0]
        for check in ('.create_new(true)', 'sync_all()?', '"/dev/urandom"', 'incident_id:'):
            self.assertIn(check, publish)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("model-quarantine-reconcile") if args.len() == 1', main)


    def test_incomplete_quarantine_retention_is_explicit_and_preserves_before_clearance(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        retain = source.split('fn reviewed_retain_incomplete_quarantine(')[1].split('pub fn quarantine_reconcile(')[0]
        for check in ('tpm::decode::<32>(reviewed)?', '.create_new(true)', 'libc::O_NOFOLLOW',
                      'file.sync_all()?', 'File::open(state)?.sync_all()?',
                      'observe_incomplete_quarantine(state, resolve)?', 'current.review != observed.review'):
            self.assertIn(check, retain)
        self.assertLess(retain.index('retained.sync_all()?'), retain.index('fs::remove_file(state.join(QUARANTINE))?'))
        for forbidden in ('systemctl', 'model-disabled', 'remove_dir', 'remove_file(archive'):
            self.assertNotIn(forbidden, retain)
        incomplete = source.split('fn incomplete_quarantine_bytes(')[1].split('fn observe_incomplete_quarantine(')[0]
        self.assertIn('serde_json::Value', incomplete)
        self.assertIn('error.is_eof()', incomplete)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('args.len() == 2 && args[1] == "--inspect-incomplete"', main)
        reconcile = source.split('pub fn quarantine_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for check in ('"--inspect-incomplete"', '"--retain-incomplete"', 'operation_lock(var)?', 'runtime_lock(var, false)?'):
            self.assertIn(check, reconcile)


if __name__ == '__main__':
    unittest.main()
