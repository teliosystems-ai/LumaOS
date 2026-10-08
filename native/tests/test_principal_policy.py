"""Installer/authentication wiring checks, not booted-image acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PrincipalPackagingTests(unittest.TestCase):
    def test_governed_login_brackets_a_new_pam_exchange_without_holding_writer_locks(self):
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        entry = governance.split('pub fn principal_check')[1].split('pub(crate) struct HistoryBinding')[0]
        self.assertLess(entry.index('PrincipalLogin::prepare'), entry.index('authentication::local(login)?'))
        self.assertLess(entry.index('authentication::local(login)?'), entry.index('PrincipalSession::new'))
        self.assertEqual(entry.count('Store::open('), 2)
        binding = governance.split('fn read_account(')[1].split('struct PrincipalSession')[0]
        for marker in ('observe_fresh(&login.exchange', 'local != &login.local',
                       'current != login.binding', 'elapsed_since(login.clock)', 'account.logout();'):
            self.assertIn(marker, binding)
        self.assertEqual(binding.count('login.registry.current()?;'), 2)
        attempt = governance.split('struct PrincipalLogin')[1].split('struct PrincipalReader')[0]
        self.assertIn('registry: crate::principal::RegistryBinding', attempt)
        self.assertNotIn('Serialize', attempt)
        self.assertNotIn('Deserialize', attempt)
        authentication = (ROOT / 'rust/luma-platform/src/authentication.rs').read_text().split('#[cfg(test)]')[0]
        self.assertLess(authentication.index('let exchange_started = authentication_budget.boundary();'),
                        authentication.index('command.spawn()?'))
        self.assertIn('boundary.boundary.require_later(&self.exchange_started)?', authentication)

    def test_admin_rotation_uses_prefix_generation_not_current_identity_for_old_history(self):
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        replay = governance.split('fn replay(')[1].split('struct PrincipalBinding')[0]
        self.assertIn('let writer = self.writer(&catalog)?;', replay)
        self.assertIn('event.principal != writer', replay)
        self.assertIn('record.principal != writer', replay)
        self.assertNotIn('event.principal != self.principal', replay)
        writer = governance.split('fn writer(')[1].split('fn payload(')[0]
        self.assertIn('catalog.resolve_principal', writer)
        self.assertIn('serde_json::to_value(&self.principal)', writer)
        self.assertIn('Some(RotationAttempt { account })', governance.split('fn service_request_at')[1])
        self.assertIn('self.account.logout();', governance.split('impl Drop for RotationAttempt')[1])
        roles = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text().split('#[cfg(test)]')[0]
        rotation = roles.split('Command::RotateAdmin')[1].split('Command::AdvancePrincipal')[0]
        for marker in ('bootstrap_admin()', 'record.enabled', 'expected_generation',
                       'enabled: true', 'state.enabled', 'checked_add(1)'):
            self.assertIn(marker, rotation)
        self.assertNotIn('write_atomic', rotation)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("admin-principal-rotate")', main)
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('"rotate-admin" if end == 4', service)

    def test_governed_generations_preserve_baseline_and_require_real_bounded_pam_projection(self):
        roles = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('AdvancePrincipal', 'expected_generation',
                       'record.uid == 1001 || !record.enabled', 'principal_states',
                       'explicit principal adoption required', 'governed principal is disabled',
                       'registry.identity(record) != *local'):
            self.assertIn(marker, roles)
        self.assertNotIn('write_atomic', roles)
        self.assertRegex(roles, r'generation\s*\.checked_add\(1\)')
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('struct PrincipalReader', 'struct PrincipalSession', 'fn principal_check(',
                       'account.observe_fresh(&login.exchange', 'let (before, first_clock) = self.replay(local)?;',
                       'let (after, last_clock) = self.replay(local)?;', 'first_clock.elapsed_since(previous)?;',
                       'principal history changed during double replay', 'self.fenced.set(true)',
                       'impl Drop for PrincipalSession', 'session_returned', 'authentication::local(login)?',
                       'account: authentication::AuthenticatedAccount'):
            self.assertIn(marker, governance)
        self.assertNotIn('pub(crate) fn resolve(', governance)
        self.assertNotIn('pub fn resolve(', governance)
        principal_projection = governance.split('struct PrincipalBinding')[1].split('pub fn principal_check')[0]
        self.assertNotIn('Serialize', principal_projection)
        self.assertNotIn('Deserialize', principal_projection)
        self.assertNotIn('std::env::', principal_projection)
        authentication = (ROOT / 'rust/luma-platform/src/authentication.rs').read_text().split('#[cfg(test)]')[0]
        projection = authentication.split('pub(crate) fn observe<T>')[1].split('pub(crate) fn identity')[0]
        self.assertIn('self.lifetime.observe', projection)
        self.assertEqual(projection.count('self.binding.identity()?'), 2)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-admin').read_text()
        self.assertIn('/var/lib/luma-os/principals/registry.json r,', profile)
        self.assertNotIn('/var/lib/luma-os/principals/registry.json rw', profile)

    def test_principal_checkpoint_is_explicit_fixed_source_and_semantic_replay_guarded(self):
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('pub fn adopt_principals(', 'platform::require_installed()?;',
                       'adoption_command(Path::new(crate::principal::REGISTRY))?',
                       'catalog.principal_registry', 'RegistryBinding::capture(self.registry_path)?',
                       'installed principal registry differs from TPM-backed authority',
                       'principal adoption must bind the current installed registry and original Admin',
                       'registry_binding', 'binding.current()?;', 'MAX_CATALOG_EVENT: u64 = 128 * 1024'):
            self.assertIn(marker, governance)
        principal = (ROOT / 'rust/luma-platform/src/principal.rs').read_text().split('#[cfg(test)]')[0]
        binding = principal.split('pub(crate) struct RegistryBinding')[1].split('pub(crate) struct AccountBinding')[0]
        self.assertIn('pin: FilePin', binding)
        self.assertIn('self.fenced.set(true)', binding)
        self.assertNotIn('Serialize', binding)
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]')[0]
        self.assertIn('principal adoption cannot accept a caller-supplied registry', service)
        self.assertIn('adoption_command(Path::new(crate::principal::REGISTRY))?', service)
        installer = (ROOT / 'rust/luma-platform/src/platform.rs').read_text()
        self.assertNotIn('adopt_principals(', installer)

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
