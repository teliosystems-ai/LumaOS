"""Admin service packaging and fixed-boundary checks, not enforcement evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AdminServicePolicyTests(unittest.TestCase):
    def test_service_is_enabled_but_never_auto_bootstrapped(self):
        assemble = (ROOT / 'native/image/assemble.py').read_text()
        self.assertIn("'luma-admin.service'", assemble)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-admin.service').read_text()
        for line in ('ConditionKernelCommandLine=luma.mode=installed',
                     'ConditionPathExists=/var/lib/luma-os/admin/bootstrap.json',
                     'ExecStart=/usr/libexec/luma-os/luma-platform admin-service',
                     'AppArmorProfile=luma-admin', 'NoNewPrivileges=yes', 'ProtectClock=yes',
                     'RestrictAddressFamilies=AF_UNIX', 'DevicePolicy=closed',
                     'DeviceAllow=/dev/tpmrm0 rw', 'CapabilityBoundingSet=CAP_CHOWN',
                     'MemoryMax=256M', 'MemorySwapMax=0', 'TasksMax=16', 'KillMode=control-group'):
            self.assertIn(line, unit)
        self.assertNotIn('admin-bootstrap', unit)
        self.assertNotIn('PrivateDevices=yes', unit)

    def test_service_has_no_secret_json_or_environment_authentication(self):
        source = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('libc::SO_PEERCRED', source)
        peer = (ROOT / 'rust/luma-platform/src/admin_service/peer.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('if credentials.uid != HUMAN', peer)
        self.assertIn('let bound = Peer::capture(stream)?;', source)
        self.assertIn('authentication::peer_account', source)
        self.assertIn('read_until(stream, password.bytes_mut(), deadline)', source)
        self.assertIn('drop(password)', source)
        self.assertNotIn('std::env::', source)
        self.assertNotIn('password: String', source)
        self.assertNotIn('password: Vec', source)
        self.assertNotIn('Operation::Bootstrap', source)
        self.assertIn('require_confined()?;', source)
        for name, fixture in (('authentication.rs', 'fixture_peer_account'),
                              ('admin_governance.rs', 'fixture_service_request')):
            implementation = (ROOT / 'rust/luma-platform/src' / name).read_text()
            self.assertIn('#[cfg(test)]\npub(crate) fn ' + fixture, implementation)
            self.assertNotIn(fixture, implementation.split('#[cfg(test)]')[0])
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertNotIn('fixture_peer_account', main)
        self.assertNotIn('fixture_service_request', main)

    def test_profile_does_not_write_enrollment_or_expose_worker_data(self):
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-admin').read_text()
        self.assertIn('{anchor.json,nv-auth.cred,parent.name,enrollment.json,bootstrap.json} r,', profile)
        self.assertNotIn('/var/lib/luma-os/admin/** rw', profile)
        self.assertIn('deny /var/lib/luma-os/models/**', profile)
        self.assertIn('deny /var/lib/luma-os/artifacts/**', profile)
        self.assertNotIn('network inet', profile)

    def test_live_peer_wraps_identity_at_catalog_authority_boundaries(self):
        peer = (ROOT / 'rust/luma-platform/src/admin_service/peer.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('pin: File', 'stream: UnixStream', 'fenced: Cell<bool>',
                       'crate::service::peer_pidfd(stream)?', 'pidfd_alive(&self.pin)?',
                       'inspect(&self.pin, self.credentials.pid)?;', 'libc::POLLRDHUP',
                       '/proc/self/fdinfo/', 'HANDLE_LIMIT: u64 = 4096',
                       'self.peer.fenced.set(true)', 'libc::fstatfs'):
            self.assertIn(marker, peer)
        self.assertNotIn('SYS_pidfd_open', peer)
        self.assertNotIn('Serialize', peer)
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        native = governance.split('pub(crate) fn service_request(')[1].split('#[cfg(test)]')[0]
        self.assertEqual(native.count('peer.observe(|| account.identity())'), 2)
        self.assertEqual(native.count('peer.check()?;'), 2)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-admin.service').read_text()
        self.assertIn('ProtectProc=invisible', unit)
        self.assertIn('CapabilityBoundingSet=CAP_CHOWN', unit)


if __name__ == '__main__':
    unittest.main()
