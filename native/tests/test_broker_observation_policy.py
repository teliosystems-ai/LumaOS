"""Read-observer confinement contract; actual enforcement requires image tests."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'image/overlay'


class BrokerObservationPolicyTests(unittest.TestCase):
    def test_only_metadata_observation_capability_and_no_tracing_syscalls(self):
        unit = (ROOT / 'etc/systemd/system/luma-broker.service').read_text()
        self.assertIn('CapabilityBoundingSet=CAP_SYS_PTRACE\n', unit)
        self.assertIn('AmbientCapabilities=\n', unit)
        self.assertIn('AppArmorProfile=luma-broker\n', unit)
        self.assertIn('SystemCallFilter=~ptrace process_vm_readv process_vm_writev', unit)
        profile = (ROOT / 'etc/apparmor.d/luma-broker').read_text()
        self.assertIn('deny ptrace (trace, tracedby),', profile)
        self.assertIn('deny /proc/@{pid}/{mem,environ} rw,', profile)
        self.assertNotIn('capability sys_admin', profile)
        self.assertNotIn('capability dac_override', profile)
        self.assertNotIn('network inet', profile)

    def test_known_workers_allow_read_observation_not_memory_or_trace(self):
        broker = (ROOT / 'etc/apparmor.d/luma-broker').read_text()
        for name in ('luma-acquisition', 'luma-qa-supervisor', 'luma-model',
                     'luma-reference', 'luma-granted-client'):
            with self.subTest(name=name):
                self.assertIn('ptrace (read) peer=' + name + ',', broker)
                worker = (ROOT / 'etc/apparmor.d' / name).read_text()
                self.assertIn('ptrace (readby) peer=luma-broker,', worker)
                self.assertNotIn('ptrace (trace) peer=luma-broker,', worker)

    def test_model_and_authority_storage_remain_read_only(self):
        profile = (ROOT / 'etc/apparmor.d/luma-broker').read_text()
        for path in ('identity', 'models', 'model-packs', 'model-qa'):
            self.assertIn('deny /var/lib/luma-os/' + path + '/** wklmx,', profile)
        self.assertIn('/sys/fs/cgroup/lumamodel.slice/** rw,', profile)
        self.assertIn('/sys/fs/cgroup/lumaacquisition.slice/** rw,', profile)
        self.assertIn('/var/lib/luma-os/resource-checkpoint/paired/** rwk,', profile)
        self.assertIn('deny /dev/{mem,kmem,port,kvm,dxg,nvidia*,dri/**} rw,', profile)


if __name__ == '__main__':
    unittest.main()
