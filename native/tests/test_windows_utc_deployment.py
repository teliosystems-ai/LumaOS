"""Image composition guards, not installed systemd/AppArmor/TPM qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / 'native/image/overlay'
UNITS = OVERLAY / 'etc/systemd/system'
POLICY = OVERLAY / 'etc/apparmor.d'


def fields(name):
    result = {}
    for line in (UNITS / name).read_text().splitlines():
        if line and not line.startswith(('#', '[')):
            key, separator, value = line.partition('=')
            if separator:
                result.setdefault(key, []).append(value)
    return result


class WindowsUtcDeploymentTests(unittest.TestCase):
    def test_publisher_and_transport_have_distinct_fixed_identities_and_budgets(self):
        publisher = fields('luma-utc-windows.service')
        front = fields('luma-utc-windows-front.service')
        for unit, user, memory, tasks, profile in (
                (publisher, 'root', '256M', '4', 'luma-utc-windows'),
                (front, 'luma-utc-front', '128M', '1', 'luma-utc-windows-front')):
            self.assertEqual(unit['User'], [user])
            self.assertEqual(unit['Group'], ['luma-utc-front'])
            self.assertEqual(unit['MemoryMax'], [memory])
            self.assertEqual(unit['TasksMax'], [tasks])
            self.assertEqual(unit['MemorySwapMax'], ['0'])
            self.assertEqual(unit['CapabilityBoundingSet'], [''])
            self.assertEqual(unit['NoNewPrivileges'], ['yes'])
            self.assertEqual(unit['AppArmorProfile'], [profile])
            self.assertEqual(unit['RestrictAddressFamilies'], ['AF_UNIX'])
            self.assertIn('OPENSSL_CONF=/dev/null', unit['Environment'][0])
            for name in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_MODULES',
                         'SSLKEYLOGFILE', 'PYTHONHOME', 'PYTHONPATH'):
                self.assertIn(name, unit['UnsetEnvironment'][0].split())
        self.assertEqual(front['LimitMEMLOCK'], ['0'])
        self.assertEqual(front['ExecStart'], ['/usr/bin/python3 -I -S -B /usr/libexec/luma-os/utc-windows-front.py'])
        self.assertEqual(publisher['DeviceAllow'], ['/dev/tpmrm0 rw'])

    def test_custody_preserves_checked_parent_child_ext4_mount_identity(self):
        for name in ('luma-content-custody.service', 'luma-utc-windows.service'):
            unit = fields(name)
            self.assertIn('/var/lib/luma-os', unit['ReadWritePaths'])
            for directive in ('ReadWritePaths', 'ReadOnlyPaths'):
                for paths in unit.get(directive, []):
                    self.assertFalse(any(p.startswith('/var/lib/luma-os/') for p in paths.split()),
                                     'a per-child bind breaks the real mount identity guard')
        publisher = (POLICY / 'luma-utc-windows').read_text()
        self.assertIn('/var/lib/luma-os/utc-windows-checkpoint/genesis.json r,', publisher)
        self.assertNotIn('/var/lib/luma-os/utc-windows/** rw', publisher)

    def test_https_requires_explicit_commissioning_and_never_autolistens(self):
        socket = fields('luma-utc-windows-front.socket')
        self.assertEqual(socket['ListenStream'], ['8443'])
        self.assertEqual(socket['Accept'], ['no'])
        self.assertEqual(socket['Backlog'], ['4'])
        self.assertNotIn('WantedBy', socket)
        for name in ('transport.json', 'certificate.pem', 'private-key.pem'):
            self.assertIn('/etc/luma-os/utc-windows/' + name, socket['ConditionPathExists'])
        assembly = (ROOT / 'native/image/assemble.py').read_text()
        self.assertNotIn("enable('luma-utc-windows-front.socket')", assembly)
        self.assertIn('windows_utc_policy.canonical_manifest', assembly)
        tmpfiles = (OVERLAY / 'etc/tmpfiles.d/luma-utc-windows.conf').read_text()
        self.assertNotIn('private-key.pem', tmpfiles)
        self.assertNotIn('certificate.pem', tmpfiles)

    def test_signing_helper_is_stacked_and_transport_has_no_authority_files(self):
        publisher = (POLICY / 'luma-utc-windows').read_text()
        helper = (POLICY / 'luma-utc-windows-crypto').read_text()
        front = (POLICY / 'luma-utc-windows-front').read_text()
        self.assertIn('rpx -> &luma-utc-windows-crypto', publisher)
        self.assertIn('deny /var/** rwklmx,', helper)
        self.assertIn('deny /run/** rwklmx,', helper)
        self.assertIn('deny /dev/{tpm*', helper)
        self.assertIn('deny /var/lib/luma-os/** rwklmx,', front)
        self.assertIn('deny /dev/{tpm*', front)
        self.assertIn('peer=(label=luma-utc-windows)', front)
        self.assertNotIn('/run/luma-broker/control.sock rw', front)


if __name__ == '__main__':
    unittest.main()
