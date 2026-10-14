"""Installer staging packaging boundaries, not installed enforcement evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'image/overlay'


class InstallerStageConfinementTests(unittest.TestCase):
    def test_only_supervisor_has_metadata_observation_capability(self):
        supervisor = (ROOT / 'etc/apparmor.d/luma-installer-model-stage').read_text()
        fetch = (ROOT / 'etc/apparmor.d/luma-installer-model-fetch').read_text()
        self.assertIn('capability sys_ptrace,', supervisor)
        self.assertIn('ptrace (read) peer=unconfined,', supervisor)
        self.assertNotIn('ptrace (trace', supervisor)
        self.assertIn('deny /proc/@{pid}/{mem,environ} rw,', supervisor)
        self.assertNotIn('capability ', fetch)
        self.assertNotIn('ptrace (', fetch)
        self.assertIn('/usr/bin/curl mrpx -> &luma-installer-model-fetch,', supervisor)

    def test_byte_worker_cannot_open_serving_or_custody_routes(self):
        supervisor = (ROOT / 'etc/apparmor.d/luma-installer-model-stage').read_text()
        for refused in ('/dev/{tpm*,mem,kmem,port,kvm,dxg,nvidia*,dri/**}',
                        '/var/lib/luma-broker/**', '/run/luma-{admin,governance,broker}/**'):
            self.assertIn('deny ' + refused, supervisor)
        for unsupported in ('llama-server', 'luma-model.service', 'model-selection.json rw',
                            'model-auth.key rw', 'model.env rw'):
            self.assertNotIn(unsupported, supervisor)
        self.assertIn('/root/usr/share/luma-os/** r,', supervisor)
        self.assertIn('/data/lib/luma-os/principals/registry.json r,', supervisor)

    def test_fetch_receives_only_inert_partial_byte_output(self):
        profile = (ROOT / 'etc/apparmor.d/luma-installer-model-fetch').read_text()
        self.assertIn('/data/lib/luma-os/models/*.partial-* w,', profile)
        self.assertIn('network inet stream,', profile)
        self.assertIn('network inet6 stream,', profile)
        for absent in ('model-packs/** rw', 'installer-model-staging/* rw',
                       '/run/luma-disk-locks/', 'memfd:luma-release', '/proc/@{pid}/fd/'):
            self.assertNotIn(absent, profile)

    def test_installer_domain_is_independent_and_physically_bounded(self):
        text = (ROOT / 'etc/systemd/system/lumainstallerstage.slice').read_text()
        for property in ('MemoryAccounting=yes', 'CPUAccounting=yes', 'IOAccounting=yes',
                         'TasksAccounting=yes', 'MemoryHigh=384M', 'MemoryMax=512M',
                         'MemorySwapMax=0', 'TasksMax=16', 'CPUQuota=200%'):
            self.assertIn(property, text.splitlines())
        self.assertNotIn('luma-broker.service', text)


if __name__ == '__main__':
    unittest.main()
