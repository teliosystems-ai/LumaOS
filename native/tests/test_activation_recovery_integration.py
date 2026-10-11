"""Read-only composition checks; these do not qualify physical recovery."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / 'rust/luma-platform/src'
OVERLAY = ROOT / 'native/image/overlay'


class ActivationRecoveryIntegration(unittest.TestCase):
    def test_root_service_and_resource_admission_are_fenced_before_effects(self):
        service = (RUST / 'service.rs').read_text().split('pub fn serve()', 1)[1]
        self.assertLess(service.index('require_production_activation()?'),
                        service.index('UnixListener::bind('))
        handler = (RUST / 'resource_manager.rs').read_text().split('pub(crate) fn handle(', 1)[1]
        self.assertLess(handler.index('require_production_activation()?'),
                        handler.index('self.maintain()?'))
        # The isolated worker obtains authority through its root broker, rather
        # than gaining access to the Admin journal or TPM credentials.
        worker = (RUST / 'model.rs').read_text().split('pub fn serve()', 1)[1]
        self.assertIn('WorkerLease::acquire(', worker)
        self.assertNotIn('require_production_activation()', worker)
        self.assertNotIn('LocalAnchor::installed()', worker)

    def test_fixed_reviewed_first_boot_commands_are_callable(self):
        main = (RUST / 'main.rs').read_text()
        launcher = (OVERLAY / 'usr/bin/luma-admin-control').read_text()
        for command in ('admin-release-trust-stage', 'admin-release-activate'):
            self.assertIn(command, main)
            self.assertIn(command, launcher)
        self.assertIn('staged_release_command(&args)', main)
        self.assertIn('/var/lib/luma-os/staged-release.json r,',
                      (OVERLAY / 'etc/apparmor.d/luma-admin').read_text())

    def test_recovery_has_a_separate_fixed_executor_and_transition(self):
        launcher = (OVERLAY / 'usr/bin/luma-recovery-control').read_text()
        self.assertIn('utc-seed|utc-reacquire|repair-a|repair-b)', launcher)
        self.assertIn('/usr/bin/env -i', launcher)
        self.assertIn('aa-exec -p luma-recovery --', launcher)
        self.assertIn('luma-platform recover "$@"', launcher)
        self.assertNotIn('eval ', launcher)
        self.assertIn("(ROOT/'usr/bin/luma-recovery-control').chmod(0o755)",
                      (ROOT / 'native/image/assemble.py').read_text())
        profile = (OVERLAY / 'etc/apparmor.d/luma-recovery').read_text()
        self.assertIn('Px -> luma-utc-recovery-restart', profile)
        self.assertNotIn('/usr/bin/bash', profile)
        self.assertNotIn('/usr/bin/systemctl', profile)
        self.assertIn('deny /var/lib/luma-os/staging/target-recovery-*/data/** wklx,', profile)
        self.assertIn('deny /efi/** rwklx,', profile)
        self.assertIn('/run/luma-admin/anchor.lock rwk,', profile)
        self.assertIn('/run/luma-utc-control/{query,control}.sock rw,', profile)

    def test_repair_lifetime_is_not_an_export_or_pam_session(self):
        source = (RUST / 'authentication/session.rs').read_text()
        repair = source.split('pub(super) struct RepairLifetime', 1)[1].split('#[cfg(test)]', 1)[0]
        self.assertIn('REPAIR_WINDOW_NS', repair)
        self.assertNotIn('EXPORT_WINDOW_NS', repair)
        self.assertNotIn('Serialize', repair)
        self.assertNotIn('renew(', repair)
        self.assertIn('check_projection', repair)
        self.assertIn('struct RepairObservation', repair)


if __name__ == '__main__':
    unittest.main()
