"""Resource integration guards, not installed enforcement qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ResourcePolicyTests(unittest.TestCase):
    def test_broker_is_the_only_resource_writer_and_uses_existing_transport(self):
        source = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertEqual(source.count('UnixListener::bind(SOCKET)'), 1)
        self.assertIn('SO_PEERPIDFD', source)
        self.assertIn('peer_pidfd(&stream)', source)
        self.assertIn('kernel peer authentication', source)
        self.assertIn('resource_manager::Manager::open()', source)
        self.assertNotIn('resources::initialize', source)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('ReadOnlyPaths=/sys/fs/cgroup', unit)
        self.assertIn('ReadWritePaths=/sys/fs/cgroup/lumamodel.slice', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)

    def test_lease_precedes_weight_loading_and_runtime_execution(self):
        source = (ROOT/'rust/luma-platform/src/model.rs').read_text()
        serve = source.split('pub fn serve()')[1].split('#[cfg(test)]')[0]
        self.assertLess(serve.index('WorkerLease::acquire'), serve.index('verified_file('))
        self.assertLess(serve.index('WorkerLease::acquire'), serve.index('supervision::run'))
        self.assertIn('lease.check()', serve)
        self.assertIn('fence.check(', serve)

    def test_physical_drainage_not_a_worker_message_returns_capacity(self):
        source = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        maintain = source.split('pub(crate) fn maintain')[1].split('pub(crate) fn handle')[0]
        self.assertIn('self.group.populated()', maintain)
        self.assertIn('self.group.current()', maintain)
        self.assertLess(maintain.index('self.group.kill()'), maintain.index('finish_draining('))
        self.assertIn('cgroup.freeze', maintain)
        self.assertNotIn('"resource-release"', source)
        drop = source.split('impl Drop for Heartbeat')[1].split('pub(crate) fn client')[0]
        self.assertNotIn('resource_exchange', drop)

    def test_installer_initializes_private_resource_state_and_model_is_cgroup_bound(self):
        platform = (ROOT/'rust/luma-platform/src/platform.rs').read_text()
        self.assertIn('crate::resources::initialize(&data.at.join("lib/luma-broker/resources"))?', platform)
        model = (ROOT/'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        for directive in ('Slice=lumamodel.slice', 'BindsTo=luma-broker.service',
                          'OOMPolicy=kill', 'MemorySwapMax=0', 'LimitMEMLOCK=0',
                          'IOReadBandwidthMax=/var 64M', 'IOWriteBandwidthMax=/var 64M',
                          'KillMode=control-group', 'ProtectControlGroups=yes'):
            self.assertIn(directive, model)
        profile = (ROOT/'native/image/overlay/etc/apparmor.d/luma-model').read_text()
        self.assertIn('/run/luma-broker/control.sock rw,', profile)
        self.assertNotIn('/var/lib/luma-broker/resources', profile)

    def test_resource_implementation_contains_no_unimplemented_paths(self):
        for name in ('resources.rs', 'resource_manager.rs'):
            source = (ROOT/'rust/luma-platform/src'/name).read_text()
            for marker in ('todo!', 'unimplemented!', '// TODO', '// FIXME'):
                self.assertNotIn(marker, source)

    def test_suspend_stops_model_execution_and_lease_deadlines_include_sleep_time(self):
        assembly = (ROOT/'native/image/assemble.py').read_text()
        self.assertIn('Conflicts=luma-reference.service luma-model.service', assembly)
        resource = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        self.assertIn('libc::CLOCK_BOOTTIME', resource)

    def test_archival_is_broker_only_reviewed_and_not_a_capacity_release(self):
        source = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        archive = source.split('"resource-archive" => {')[1].split('_ => return Err')[0]
        self.assertIn('self.group.populated()', archive)
        self.assertIn('self.owners.is_empty()', archive)
        self.assertIn('self.store.archive(', archive)
        ledger = (ROOT/'rust/luma-platform/src/resources.rs').read_text()
        cut = ledger.split('pub(crate) fn archive(')[1].split('fn transaction')[0]
        self.assertIn('State::Released', cut)
        self.assertIn('l.leases.clear()', cut)
        self.assertNotIn('l.generation =', cut)
        self.assertNotIn('remove_file', cut)

    def test_idle_reclaim_requires_empty_group_and_observed_bytes_not_write_success(self):
        resource = (ROOT/'rust/luma-platform/src/resource_manager.rs').read_text()
        reclaim = resource.split('fn reclaim_idle')[1].split('fn oom')[0]
        self.assertIn('self.populated()', reclaim)
        self.assertIn('memory.reclaim', reclaim)
        self.assertIn('libc::EAGAIN', reclaim)
        maintain = resource.split('pub(crate) fn maintain')[1].split('pub(crate) fn handle')[0]
        actual = maintain.split('self.group.reclaim_idle()?;')[1]
        self.assertLess(actual.index('self.group.current()?'), actual.index('l.observe('))

    def test_socket_uses_service_user_acl_without_world_or_shared_database_group(self):
        service = (ROOT/'rust/luma-platform/src/service.rs').read_text()
        self.assertIn('restrict_socket(Path::new(SOCKET))?', service)
        self.assertIn('system.posix_acl_access', service)
        self.assertNotIn('from_mode(0o666)', service)
        self.assertIn('no permissive fallback', service)
        unit = (ROOT/'native/image/overlay/etc/systemd/system/luma-model.service').read_text()
        self.assertNotIn('SupplementaryGroups=luma-control', unit)


if __name__ == '__main__':
    unittest.main()
