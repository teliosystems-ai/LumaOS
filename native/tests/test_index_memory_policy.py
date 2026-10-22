"""Source wiring only: no loaded cgroup/LSM or native authorization claim."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
UNITS = ROOT / 'native/image/overlay/etc/systemd/system'
POLICY = ROOT / 'native/image/overlay/etc/apparmor.d'
RUST = ROOT / 'rust/luma-platform/src'


class IndexMemoryPolicyTests(unittest.TestCase):
    def test_private_index_request_and_output_are_exact_inherited_descriptors(self):
        worker = (POLICY / 'luma-acquisition').read_text()
        client = (POLICY / 'luma-granted-client').read_text()
        self.assertIn('/memfd:luma-index-request r,', worker)
        self.assertIn('/memfd:luma-index-output rw,', worker)
        self.assertNotIn('/memfd:luma-index-request rw,', worker)
        self.assertIn('/memfd:luma-index-{request,output} rw,', client)
        for policy in (worker, client):
            self.assertNotIn('/memfd:luma-index-* rw,', policy)
            self.assertNotIn('/memfd:* rw,', policy)

    def test_parent_exists_before_broker_without_a_c_service_dependency_cycle(self):
        parent = (UNITS / 'system-lumacustody.slice').read_text()
        broker = (UNITS / 'luma-broker.service').read_text()
        child = (UNITS / 'luma-content-custody.service').read_text()
        self.assertIn('Before=luma-broker.service luma-content-custody.service', parent)
        self.assertIn('MemoryMax=128M', parent)
        self.assertIn('MemorySwapMax=0', parent)
        self.assertIn('TasksMax=2', parent)
        self.assertIn('CPUQuota=25%', parent)
        self.assertIn('system-lumacustody.slice', broker.split('[Service]')[0])
        self.assertNotIn('Requires=luma-content-custody.service', broker)
        self.assertIn('Slice=system-lumacustody.slice', child)
        self.assertIn('MemoryMax=256M', child)
        self.assertIn('CapabilityBoundingSet=\n', child)

    def test_broker_can_write_only_the_fixed_c_parent_memory_control(self):
        unit = (UNITS / 'luma-broker.service').read_text()
        policy = (POLICY / 'luma-broker').read_text()
        exact = '/sys/fs/cgroup/system.slice/system-lumacustody.slice/memory.max'
        self.assertIn('ReadWritePaths=' + exact + '\n', unit)
        self.assertIn(exact + ' rw,', policy)
        for forbidden in ('/sys/fs/cgroup/system.slice/** rw,',
                          '/sys/fs/cgroup/system.slice/system-lumacustody.slice/** rw,',
                          '/sys/fs/cgroup/system.slice/system-lumacustody.slice/cgroup.kill rw,'):
            self.assertNotIn(forbidden, policy)
        writes = [line.strip() for line in policy.splitlines()
                  if 'system-lumacustody.slice' in line and 'rw' in line]
        self.assertEqual(writes, [exact + ' rw,'])

    def test_c_installed_identity_is_read_only_not_owner_or_raw_disk_access(self):
        policy = (POLICY / 'luma-content-custody').read_text()
        self.assertIn('/usr/share/luma-os/source-lock.json r,', policy)
        self.assertIn('/sys/devices/virtual/block/dm-[0-9]*/dm/{name,uuid} r,', policy)
        self.assertIn('/sys/devices/**/partition r,', policy)
        self.assertIn('deny /var/lib/luma-os/content-store/** rwklmx,', policy)
        for line in policy.splitlines():
            if line.strip().startswith('/sys/'):
                self.assertTrue(line.strip().endswith(' r,'), line)
        self.assertNotIn('/dev/sd* r,', policy)
        self.assertNotIn('/dev/nvme* r,', policy)

    def test_one_cgroup_identity_and_strong_liability_retention_are_joined(self):
        memory = (RUST / 'resource_manager/custody_memory.rs').read_text()
        manager = (RUST / 'resource_manager.rs').read_text()
        protocol = (RUST / 'content_custody/protocol.rs').read_text()
        peer = (RUST / 'resource_manager/peer.rs').read_text()
        self.assertIn('/system.slice/system-lumacustody.slice/luma-content-custody.service', memory)
        for source in (protocol, peer):
            self.assertIn('CUSTODY_LEAF', source)
            self.assertNotIn('/system.slice/luma-content-custody.service', source)
        for fence in ('profile.worker_memory()?', 'self.custody_memory.maintain(&ledger)?',
                      'self.custody_memory.begin(', 'self.custody_memory.finish('):
            self.assertIn(fence, manager)
        for fence in ('self.parent.set_cap(BASE)?', 'self.parent.set_cap(INDEX_C)?',
                      'worker.populated()?', 'charge.process.check(&child)?',
                      'ACQUISITION_MEMORY,'):
            self.assertIn(fence, memory)


if __name__ == '__main__':
    unittest.main()
