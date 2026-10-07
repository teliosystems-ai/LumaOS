"""Installer/authentication wiring checks, not booted-image acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PrincipalPackagingTests(unittest.TestCase):
    def test_fresh_install_creates_principals_after_account_initialization(self):
        source = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        create = source.index('create_identity(&data.at,')
        principals = source.index('crate::principal::initialize(')
        self.assertLess(create, principals)
        self.assertLess(principals, source.index('INSTALLATION COMPLETE:'))
        self.assertIn('&[(&user, 1000), (&admin, 1001)]', source)

    def test_product_authentication_uses_fixed_registry_and_never_initializes_it(self):
        source = (ROOT / 'rust/luma-platform/src/authentication.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('Path::new(principal::REGISTRY)', source)
        self.assertIn('Path::new(principal::IDENTITY)', source)
        self.assertNotIn('principal::initialize', source)
        self.assertIn('binding.current_uid()? != uid', source)
        self.assertIn('"product_admin_active":false', source)

    def test_pam_sessions_use_suspend_aware_bounded_nonrestorable_lifetimes(self):
        authentication = (ROOT / 'rust/luma-platform/src/authentication.rs').read_text().split('#[cfg(test)]')[0]
        session = (ROOT / 'rust/luma-platform/src/authentication/session.rs').read_text()
        for marker in ('mod session;', 'lifetime: session::Lifetime',
                       'self.lifetime.observe(|| self.binding.identity())',
                       'self.lifetime.observe(|| self.binding.current_uid())',
                       'authentication_budget.check()?;', 'impl Drop for AuthenticatedAccount',
                       'self.lifetime.close()'):
            self.assertIn(marker, authentication)
        for marker in ('libc::CLOCK_BOOTTIME', 'WINDOW_NS: u64 = 30_000_000_000',
                       'now.boottime_ns >= self.deadline_ns', 'now.boottime_ns < self.last_ns.get()',
                       'now.process != self.issued.process', 'now.uid != self.issued.uid',
                       'now.boot != self.issued.boot', 'self.phase.get() != Phase::Active',
                       'struct Observation', 'self.lifetime.fence()', 'impl Drop for Lifetime',
                       'libc::O_NOFOLLOW', 'libc::fstatfs', 'filesystem.f_type != 0x9fa0'):
            self.assertIn(marker, session)
        self.assertNotIn('clock_settime', session)
        self.assertNotIn('Deserialize', session.split('pub(super) struct Lifetime')[1].split('struct Observation')[0])
        self.assertIn('#[cfg(test)]\n    pub(super) fn expired_fixture', session)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-admin').read_text()
        self.assertIn('/proc/sys/kernel/random/boot_id r,', profile)
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        self.assertEqual(governance.count('authenticated.logout();'), 3)
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('account.logout();', service)

    def test_account_bindings_pin_original_files_and_recheck_after_reads(self):
        source = (ROOT / 'rust/luma-platform/src/principal.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('struct FilePin', 'pins: [FilePin; 3]',
                       'pins: [registry_pin, passwd_pin, shadow_pin]',
                       'libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC',
                       'FileIdentity::of(&self.file.metadata()?)',
                       'FileIdentity::of(&fs::symlink_metadata(&self.path)?)',
                       'DirectoryIdentity::of(&self.parent.metadata()?)',
                       'pin.complete_read()?;', 'passwd_pin.recheck()?;',
                       'shadow_pin.recheck()?;', 'binding.recheck_pins()?;'):
            self.assertIn(marker, source)
        revalidation = source.split('fn revalidate(&self)')[1].split('fn recheck_pins')[0]
        self.assertEqual(revalidation.count('self.recheck_pins()?;'), 2)
        self.assertIn('pin.file.read_exact(bytes.bytes_mut())?;', source)
        self.assertNotIn('fs::read_to_string', source)


if __name__ == '__main__':
    unittest.main()
