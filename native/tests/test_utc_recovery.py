"""Recovery UTC composition, not firmware, clock or native NTS qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / 'rust/luma-platform/src'
ASSETS = ROOT / 'native/image/utc'
PROFILES = ROOT / 'native/image/overlay/etc/apparmor.d'


class RecoveryUtc(unittest.TestCase):
    def test_installed_and_recovery_construction_have_distinct_sealed_image_checks(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        mode = runtime.split('pub(crate) enum Mode {', 1)[1].split('/// This cannot be deserialized', 1)[0]
        self.assertIn('Recovery(crate::platform::RecoveryImage)', mode)
        self.assertIn('crate::platform::require_installed()?', mode)
        self.assertIn('crate::platform::RecoveryImage::current()?', mode)
        self.assertIn('Self::Recovery(image) => image.recheck()', mode)
        for name in ('luma-utc-producer', 'luma-utc-recovery-producer',
                     'luma-utc-keeper', 'luma-utc-recovery-keeper'):
            self.assertIn(name + ' (enforce)', mode)
            self.assertIn('/system.slice/' + name + '.service', mode)
        self.assertIn('self.mode.producer_label()', runtime)
        self.assertIn('self.mode.producer_cgroup()', runtime)
        for check in ('mapping_inventory(', 'controls(', 'environment(',
                      'Identity::of(&executable) != *approved', 'readonly(&pin.file)?'):
            self.assertIn(check, runtime)

    def test_recovery_client_never_takes_caller_target_history_time_or_boolean(self):
        source = (RUST / 'utc_provider/recovery.rs').read_text()
        fields = source.split('pub(crate) struct RecoveryClient', 1)[1].split('impl<', 1)[0]
        self.assertIn('TargetAuthority', fields)
        self.assertNotIn('pub ', fields)
        self.assertNotIn('Serialize', fields)
        current = source.split('pub(crate) fn current(', 1)[1].split('pub(crate) fn project_after_checks(', 1)[0]
        current = ''.join(current.split())
        self.assertIn('self.authority.history_binding()', current)
        self.assertLess(current.index('self.authority.observe_history('),
                        current.index('self.client.project_after_checks('))
        self.assertIn('self.authority.check_projection(clock)', current)
        self.assertIn('self.client.fenced = true', source)
        for verb in ('recovery_seed_proposal', 'recovery_deliver_seed',
                     'recovery_reacquire_proposal', 'recovery_reacquire'):
            body = source.split('pub(crate) fn ' + verb + '(', 1)[1].split('\n}\n', 1)[0]
            self.assertIn('TargetAuthority', body)
            self.assertIn('authority.observe_history(authority.history_binding()', body)
        for forbidden in ('PathBuf', 'trusted: bool', 'chroot', 'clock_settime(', 'Interval::new('):
            self.assertNotIn(forbidden, source.split('#[cfg(test)]', 1)[0])

    def test_keeper_is_independent_of_target_tpm_secrets_and_network(self):
        unit = (ASSETS / 'luma-utc-recovery-keeper.service').read_text()
        profile = (PROFILES / 'luma-utc-recovery-keeper').read_text()
        for required in ('ConditionKernelCommandLine=luma.mode=live',
                         'utc-recovery-keeper', 'Restart=no', 'PrivateDevices=yes',
                         'DevicePolicy=closed', 'RestrictAddressFamilies=AF_UNIX',
                         'CapabilityBoundingSet=CAP_CHOWN CAP_SYS_PTRACE CAP_SYS_TIME'):
            self.assertIn(required, unit)
        self.assertIn('ptrace (read) peer=luma-utc-recovery-producer', profile)
        self.assertIn('deny /dev/{tpm*', profile)
        self.assertIn('deny /run/luma-recovery/** rwklx', profile)
        self.assertIn('deny /var/lib/luma-os/** rwklx', profile)
        self.assertIn('/sys/firmware/efi/efivars/{SecureBoot,SetupMode}-', profile)
        self.assertNotIn('network inet', profile)
        self.assertNotIn('ptrace (trace)', profile)
        self.assertNotIn('capability sys_admin', profile)
        self.assertNotIn('DeviceAllow=', unit)

    def test_seed_cannot_start_network_producer_without_the_exact_fixed_keeper(self):
        producer = (ASSETS / 'luma-utc-recovery-producer.service').read_text()
        path = (ASSETS / 'luma-utc-recovery-producer.path').read_text()
        for value in ('luma-utc-recovery-keeper.service', 'ConditionKernelCommandLine=luma.mode=live',
                      'ConditionPathExists=/run/luma-utc/seed-ready',
                      'ConditionPathExists=/run/luma-utc/measurements.sock',
                      'chronyd -n -U -f /usr/share/luma-os/utc/chrony.conf',
                      'User=luma-utc-producer', 'Restart=no'):
            self.assertIn(value, producer)
        self.assertIn('PathExists=/run/luma-utc/seed-ready', path)
        self.assertIn('Unit=luma-utc-recovery-producer.service', path)
        for name in ('keeper.service', 'producer.service', 'producer.path'):
            self.assertIn('luma-utc-' + name, producer)
        self.assertNotIn('BindReadOnlyPaths=/var/lib/luma-os/identity', producer)
        provider = (RUST / 'utc_provider.rs').read_text()
        self.assertIn('release.mode.query_labels()', provider)
        self.assertIn('release.mode.control_label()', provider)
        self.assertIn('credentials(&socket, self.release.mode.keeper_label())?', provider)

    def test_reacquisition_compiles_fixed_separate_units_and_authenticated_controller(self):
        helper = (RUST / 'utc_restart.c').read_text()
        recovery = helper.split('#ifdef LUMA_UTC_RECOVERY', 1)[1].split('#else', 1)[0]
        for value in ('"luma-recovery (enforce)"', '"luma-utc-recovery-restart (enforce)\\n"',
                      '"luma-utc-recovery-keeper.service"', '"luma-utc-recovery-producer.path"'):
            self.assertIn(value, recovery)
        self.assertIn('argc != 1', helper)
        self.assertIn('SO_PEERPIDFD', helper)
        self.assertIn('SO_PEERSEC', helper)
        self.assertNotIn('argv[1]', helper)
        profile = (PROFILES / 'luma-utc-recovery-restart').read_text()
        self.assertIn('signal (send,receive) peer=luma-recovery', profile)
        self.assertNotIn('peer=luma-admin', profile)

    def test_recovery_artifacts_cannot_be_removed_from_the_immutable_runtime_inventory(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        package = (ASSETS / 'package_runtime.py').read_text()
        for role, path in (
            ('recovery_service', '/usr/lib/systemd/system/luma-utc-recovery-producer.service'),
            ('recovery_confinement', '/etc/apparmor.d/luma-utc-recovery-producer'),
        ):
            self.assertIn(role, runtime)
            self.assertIn(role, package)
            self.assertIn(path, runtime)
            self.assertIn(path, package)
        for role in ('provenance', 'source_inputs'):
            self.assertIn(role, runtime)
            self.assertIn(role, package)

    def test_kernel_root_machine_query_does_not_expand_seed_or_recovery_authority(self):
        runtime = (RUST / 'utc_runtime.rs').read_text()
        query = runtime.split('pub(crate) fn query_labels(', 1)[1].split('pub(crate) fn control_label(', 1)[0]
        installed, recovery = query.split('Self::Recovery(_)', 1)
        self.assertIn('"unconfined"', installed)
        self.assertNotIn('"unconfined"', recovery)
        control = runtime.split('pub(crate) fn control_label(', 1)[1].split('\n}', 1)[0]
        self.assertNotIn('unconfined', control)
        provider = (RUST / 'utc_provider.rs').read_text()
        peer = provider.split('fn credentials_any(', 1)[1].split('#[derive(PartialEq', 1)[0]
        self.assertIn('protected_peer_ids(value.uid, value.gid, value.pid)', peer)
        self.assertIn('uid == 0 && gid == 0 && pid > 0', peer)
        self.assertIn('SO_PEERCRED', peer)
        self.assertIn('SO_PEERSEC', peer)
        self.assertIn('label.as_bytes()', peer)

    def test_producer_paths_do_not_close_a_boot_ordering_cycle(self):
        # Sequence-17 serial logs: systemd broke a cycle by skipping paths.target
        # (disk) or the recovery producer path (optical). A default path unit is
        # Before=paths.target, which precedes basic.target and so the keeper.
        def fields(name):
            values = {}
            for line in (ASSETS / name).read_text().splitlines():
                key, separator, value = line.partition('=')
                if separator and not line.startswith('#'):
                    values.setdefault(key, []).extend(value.split())
            return values
        for keeper in ('luma-utc-keeper', 'luma-utc-recovery-keeper'):
            path = fields(keeper.replace('keeper', 'producer') + '.path')
            self.assertNotIn('DefaultDependencies', fields(keeper + '.service'))
            self.assertIn(keeper + '.service', path['After'])
            self.assertIn(keeper + '.service', path['BindsTo'])
            self.assertEqual(path['DefaultDependencies'], ['no'])
            for key, unit in (('After', 'sysinit.target'), ('Requires', 'sysinit.target'),
                              ('Conflicts', 'shutdown.target'), ('Before', 'shutdown.target')):
                self.assertIn(unit, path[key])
            self.assertEqual(path['Before'], ['shutdown.target'])
            self.assertEqual(path['WantedBy'], ['multi-user.target'])


if __name__ == '__main__':
    unittest.main()
