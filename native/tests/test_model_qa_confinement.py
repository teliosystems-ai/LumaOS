"""Closed QA deployment contract, not native execution or certification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / 'native/image/overlay/etc/apparmor.d'


class ModelQaConfinementTests(unittest.TestCase):
    def test_runtime_keeps_parent_confinement_and_adds_child_restrictions(self):
        supervisor = (POLICY / 'luma-qa-supervisor').read_text()
        self.assertIn('llama-server mrpx -> &luma-model-qa,', supervisor)
        self.assertIn('/usr/libexec/luma-os/llama/*.so* mr,', supervisor)
        child = (POLICY / 'luma-model-qa').read_text()
        self.assertIn('/memfd:luma-qa-key r,', child)
        self.assertNotIn('/memfd:luma-qa-key rw', child)
        self.assertNotIn('capability ', child)
        for refused in ('/run/luma-broker/**', '/var/lib/luma-os/admin/**',
                        '/var/lib/luma-os/identity/**', '/var/lib/luma-os/model-auth/**'):
            self.assertIn('deny ' + refused, child)

    def test_supervisor_is_separate_from_ordinary_acquisition(self):
        supervisor = (POLICY / 'luma-qa-supervisor').read_text()
        acquisition = (POLICY / 'luma-acquisition').read_text()
        self.assertIn('capability sys_ptrace,', supervisor)
        self.assertIn('ptrace (read) peer=luma-model-qa,', supervisor)
        self.assertNotIn('capability sys_ptrace,', acquisition)
        self.assertNotIn('llama-server', acquisition)
        self.assertIn('/run/luma-model-qa/*/input.json r,', supervisor)
        self.assertIn('/run/luma-model-qa/*/report.json rw,', supervisor)

    def test_actual_launcher_preserves_no_new_privileges_and_private_runtime(self):
        source = (ROOT / 'rust/luma-platform/src/model/qa.rs').read_text()
        for fixed in ('NoNewPrivileges=yes', 'PrivateDevices=yes', 'MemorySwapMax=0',
                      'DevicePolicy=closed', 'IPAddressDeny=any', 'IPAddressAllow=localhost',
                      'PR_CAPBSET_DROP', 'PR_SET_PDEATHSIG', 'LD_LIBRARY_PATH', '--no-webui'):
            self.assertIn(fixed, source)
        self.assertIn('SystemCallFilter=~@mount @reboot @swap @raw-io @debug', source)
        self.assertNotIn('NoNewPrivileges=no', source)
        self.assertNotIn('SystemCallFilter=~@privileged', source)


if __name__ == '__main__':
    unittest.main()
