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
        self.assertIn('verified_runtime_file(&file, &p, || lease.check_local())?', serve)
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
        self.assertLess(serve.index('activation_records_absent('), serve.index('selected()?'))
        self.assertLess(serve.index('quarantine_absent('), serve.index('selected()?'))
        self.assertLess(serve.index('validation::worker_admission('), serve.index('verified_runtime_file('))
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
        self.assertIn('crate::acquisition::run(var, p, "prepare")', prepare)
        self.assertIn('fetch(&file, p, &mut check)?', prepare)
        self.assertIn('check_acquisition(p, available_space(&models)?, true)?', prepare)
        self.assertIn('check_acquisition(p, available_space(&models)?, false)?', prepare)
        self.assertNotIn('fetch(', activate)
        self.assertIn('verify_file(&models.join', activate)
        self.assertLess(install.index('prepare_model('),
                        install.index('"stop", "luma-model.service"'))
        self.assertLess(install.index('"stop", "luma-model.service"'),
                        install.index('activate_cached_with('))
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
        self.assertLess(install.index('model-health.py'), install.index('model_service_running('))
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


    def test_validation_trial_precedes_activation_publication_and_health_completion(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        activate = source.split('fn activate_cached_with<')[1].split('fn write_candidate_config(')[0]
        self.assertLess(activate.index('begin_activation('), activate.index('before_publication(&state, p)?'))
        self.assertLess(activate.index('before_publication(&state, p)?'), activate.index('finish_activation('))
        install = source.split('pub fn install(id: &str)')[1].split('pub fn unit()')[0]
        self.assertIn('validation::Guard::begin', install)
        self.assertLess(install.index('model-health.py'), install.index('trial.complete(&p)'))
        self.assertIn('RestartStage::Validation', install)
        self.assertIn('trial.check(&p)?', install)
        self.assertIn('publish_quarantine(', install)

    def test_validation_worker_checks_twice_without_reference_environment_permission(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertEqual(serve.count('validation::worker_admission('), 2)
        self.assertLess(serve.index('validation::worker_admission('), serve.index('verified_runtime_file('))
        self.assertLess(serve.index('verified_runtime_file('), serve.rindex('validation::worker_admission('))
        self.assertLess(serve.rindex('validation::worker_admission('), serve.index('supervision::run('))
        validation = (ROOT / 'rust/luma-platform/src/model/validation.rs').read_text()
        worker_inputs = validation.split('fn worker_hashes(')[1].split('fn consistent_current(')[0]
        self.assertNotIn('REFERENCE_ENV', worker_inputs)
        self.assertIn('model-auth/api-key', worker_inputs)
        self.assertIn('libc::F_GETLK', validation)
        self.assertIn('libc::F_SETLK', validation)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        for rule in ('/proc/[0-9]*/stat r,', '/var/lib/luma-os/model-validation.lock rk,',
                     '/var/lib/luma-os/model-validation.pending r,'):
            self.assertIn(rule, profile)
        self.assertNotIn('/var/lib/luma-os/model-reference.env', profile)
        self.assertNotIn('/var/lib/luma-os/model-validation.retained.', profile)

    def test_validation_recovery_is_explicit_root_locked_retention_without_service_start(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        reconcile = source.split('pub fn validation_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for check in ('require_root()?', 'require_installed()?', 'operation_lock(var)?',
                      'runtime_lock(var, false)?', '"--retain-abandoned"'):
            self.assertIn(check, reconcile)
        for forbidden in ('systemctl', 'model-disabled', '"key":', '"environment":'):
            self.assertNotIn(forbidden, reconcile)
        validation = (ROOT / 'rust/luma-platform/src/model/validation.rs').read_text()
        retain = validation.split('pub(super) fn retain_abandoned(')[1].split('fn retain_bytes(')[0]
        self.assertLess(retain.index('retain_bytes('), retain.index('fs::remove_file(state.join(PENDING))'))
        self.assertIn('current.review != observed.review', retain)
        self.assertNotIn('remove_file(archive', retain)
        archive = validation.split('fn retain_bytes(')[1].split('type FileIdentity')[0]
        for check in ('.create_new(true)', 'libc::O_NOFOLLOW', '.mode(0o600)',
                      'sync_all()?', 'File::open(state)?.sync_all()?'):
            self.assertIn(check, archive)
        self.assertNotIn('remove_file', archive)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("model-validation-reconcile") if args.len() == 1', main)

    def test_incomplete_validation_recovery_is_eof_only_and_identity_reviewed(self):
        validation = (ROOT / 'rust/luma-platform/src/model/validation.rs').read_text()
        incomplete = validation.split('fn incomplete_bytes(')[1].split('fn inspect_incomplete_locked(')[0]
        for check in ('serde_json::Value', 'error.is_eof()', 'file_identity(&before)',
                      'file_identity(&after)', 'record_bytes(state)?'):
            self.assertIn(check, incomplete)
        retain = validation.split('pub(super) fn retain_incomplete(')[1].split('#[cfg(test)]')[0]
        for check in ('recovery_lock(state)?', 'current.review != observed.review',
                      'checked_recovery_lock(state, &lease)?'):
            self.assertIn(check, retain)
        self.assertRegex(retain, r'observed\s*\.identity\s*\.ok_or\("incomplete validation identity missing"\)')
        self.assertLess(retain.index('retain_bytes('), retain.index('fs::remove_file(state.join(PENDING))'))
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        reconcile = source.split('pub fn validation_reconcile(')[1].split('fn legacy_configuration_at(')[0]
        for flag in ('"--inspect-incomplete"', '"--retain-incomplete"'):
            self.assertIn(flag, reconcile)
        for forbidden in ('systemctl', 'fetch(', '"key":', '"environment":'):
            self.assertNotIn(forbidden, reconcile)

    def test_validation_recovery_holds_exclusive_lock_and_checks_posix_owner(self):
        validation = (ROOT / 'rust/luma-platform/src/model/validation.rs').read_text()
        acquire = validation.split('fn recovery_lock(')[1].split('fn inspect_locked(')[0]
        for check in ('lock_file(state, false)?', 'libc::LOCK_EX | libc::LOCK_NB',
                      'query_lock(lease)?.is_some()', 'checked_lock(state, lease)?'):
            self.assertIn(check, acquire)
        for function, end in (('retain_abandoned', 'fn retain_bytes('),
                              ('retain_incomplete', '#[cfg(test)]')):
            retain = validation.split('pub(super) fn ' + function + '(')[1].split(end)[0]
            self.assertLess(retain.index('let lease = recovery_lock(state)?'), retain.index('retain_bytes('))
            self.assertLess(retain.rindex('checked_recovery_lock(state, &lease)?'),
                            retain.index('fs::remove_file(state.join(PENDING))'))
        guard = validation.split('pub(super) fn begin(')[1].split('pub(super) fn check(')[0]
        self.assertLess(guard.index('libc::LOCK_EX | libc::LOCK_NB'), guard.index('libc::F_SETLK'))

    def test_model_owned_child_is_supervised_after_verified_admission(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        for check in ('supervision::Fence::capture(', 'inherit_runtime_files(&mut command, &verified, &runtime)',
                      'supervision::run(&mut command', 'fence.check('):
            self.assertIn(check, serve)
        self.assertLess(serve.index('verified_runtime_file('), serve.index('supervision::Fence::capture('))
        self.assertNotIn('command.exec()', serve)
        supervision = (ROOT / 'rust/luma-platform/src/model/supervision.rs').read_text().split('#[cfg(test)]')[0]
        for check in ('Duration::from_millis(500)', 'recovery_disablement_absent(state)?',
                      'validation::worker_admission(state, p)?', 'self.trial = trial',
                      'validation::worker_hashes(state)? != self.hashes', 'owned.terminate()?'):
            self.assertIn(check, supervision)
        self.assertLess(supervision.index('check()?;'), supervision.index('command.spawn()?'))
        for forbidden in ('systemctl', 'remove_file(', 'fs::write(', 'killpg(', 'Command::new('):
            self.assertNotIn(forbidden, supervision)

    def test_acquisition_uses_owned_supervision_after_credential_change(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        fetch = source.split('fn fetch(')[1].split('fn operation_lock(')[0]
        confine = source.split('fn confine_acquisition(')[1].split('fn fetch(')[0]
        for check in ('libc::setgroups(', 'libc::setgid(988)', 'libc::setuid(988)',
                      'libc::PR_SET_NO_NEW_PRIVS', 'libc::RLIMIT_FSIZE',
                      'max_bytes == 0 || max_bytes >= libc::RLIM_INFINITY'):
            self.assertIn(check, confine)
        for check in ('confine_acquisition(&mut process, p.bytes)?',
                      'supervision::run(&mut process', 'crate::resource_manager::now()',
                      'checked_add(3_620_000)', 'metadata.len() > p.bytes',
                      'temporary.identity', 'libc::O_NOFOLLOW | libc::O_NONBLOCK'):
            self.assertIn(check, fetch)
        self.assertLess(fetch.index('confine_acquisition('), fetch.index('supervision::run('))
        self.assertLess(fetch.index('supervision::run('), fetch.index('verified_runtime_file('))
        for forbidden in ('child.try_wait()', 'process.spawn()', 'libc::SIGTERM',
                          'libc::kill(', 'child.kill()'):
            self.assertNotIn(forbidden, fetch)

    def test_partial_cleanup_requires_created_identity_and_independent_writer_fence(self):
        source = (ROOT / 'rust/luma-platform/src/model.rs').read_text()
        cleanup = source.split('impl Drop for Temporary')[1].split('fn fetch(')[0]
        for check in ('self.identity.ok_or(', 'open_regular(&self.path)',
                      '(metadata.dev(), metadata.ino()) != identity', 'metadata.uid() != 0',
                      'metadata.nlink() != 1', 'libc::LOCK_EX | libc::LOCK_NB',
                      'fs::symlink_metadata(&self.path)', '(named.dev(), named.ino()) != identity',
                      'sync_all()?'):
            self.assertIn(check, cleanup)
        self.assertLess(cleanup.index('libc::flock('), cleanup.index('fs::remove_file('))
        self.assertLess(cleanup.index('fs::symlink_metadata('), cleanup.index('fs::remove_file('))

    def test_model_parent_death_registration_and_child_reap_are_explicit(self):
        supervision = (ROOT / 'rust/luma-platform/src/model/supervision.rs').read_text()
        arm = supervision.split('fn arm_parent_death(')[1].split('struct OwnedRuntime')[0]
        for check in ('libc::PR_SET_PDEATHSIG', 'libc::SIGKILL', 'libc::getppid() != parent',
                      'libc::ECHILD', 'command.pre_exec'):
            self.assertIn(check, arm)
        self.assertLess(arm.index('libc::PR_SET_PDEATHSIG'), arm.index('libc::getppid() != parent'))
        terminate = supervision.split('fn terminate(')[1].split('impl Drop')[0]
        self.assertLess(terminate.index('libc::SYS_pidfd_send_signal'), terminate.index('self.observe(libc::WEXITED)'))
        self.assertIn('if self.reaped', terminate)
        self.assertIn('impl Drop for OwnedRuntime', supervision)

    def test_model_signaling_and_waiting_are_pid_handle_bound_without_pid_fallback(self):
        supervision = (ROOT / 'rust/luma-platform/src/model/supervision.rs').read_text().split('#[cfg(test)]')[0]
        for check in ('libc::SYS_pidfd_open', 'libc::SYS_pidfd_send_signal', 'libc::P_PIDFD',
                      'libc::SA_NOCLDWAIT', 'action.sa_sigaction != libc::SIG_DFL'):
            self.assertIn(check, supervision)
        run = supervision.split('pub(super) fn run(')[1].split('fn require_waitable_children(')[0]
        self.assertLess(run.index('require_waitable_children()?'), run.index('command.spawn()?'))
        self.assertLess(run.index('OwnedRuntime::pin(&child)?'), run.index('owned.poll()?'))
        for forbidden in ('child.kill()', 'child.wait()', 'libc::kill(', 'waitpid('):
            self.assertNotIn(forbidden, supervision)

    def test_model_supervision_keeps_cgroup_teardown_and_narrow_signal_permissions(self):
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('signal (send, receive) set=(kill) peer=luma-model,', profile)
        self.assertIn('/var/lib/luma-os/model-disabled r,', profile)
        self.assertNotIn('signal (send) peer=unconfined', profile)
        self.assertNotIn('/var/lib/luma-os/model-reference.env', profile)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        for setting in ('KillMode=control-group', 'TimeoutStopSec=15', 'TasksMax=64',
                        'MemorySwapMax=0', 'Restart=on-failure'):
            self.assertIn(setting, unit)

    def test_model_supervision_fixture_is_static_test_only_and_in_boundary_evidence(self):
        validation = (ROOT / 'rust/luma-platform/src/model/validation.rs').read_text()
        production, tests = validation.split('#[cfg(test)]', 1)
        self.assertNotIn('model_supervision_fixture.c', production)
        self.assertIn('include_str!', tests)
        self.assertIn('../../../../native/tests/model_supervision_fixture.c', tests)
        self.assertNotIn('LUMA_MODEL_TEST_LEAF', tests)
        for runner in ('run_storage_boundaries.sh', 'run_recovery_export.sh', 'run_tpm_boundaries.sh'):
            source = (ROOT / 'native/tests' / runner).read_text()
            self.assertIn('rust/luma-platform/src/model/*.rs', source)
            self.assertIn('native/tests/model_supervision_fixture.c', source)


if __name__ == '__main__':
    unittest.main()
