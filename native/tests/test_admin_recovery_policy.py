"""Recovery composition/source checks, not installed ceremony qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class OfflineAdminRecoveryTests(unittest.TestCase):
    def test_secrets_never_use_serialization_arguments_files_or_stdout(self):
        source = (ROOT / 'rust/luma-platform/src/admin_recovery.rs').read_text().split('#[cfg(test)]\nmod tests')[0]
        credential = source.split('pub(crate) struct Credential')[1].split('fn terminal()')[0]
        self.assertIn('PrivateBuffer', credential)
        for forbidden in ('Serialize', 'Deserialize', 'Debug', 'Clone', 'println!', 'env::', 'Command::', 'fs::write', 'to_string'):
            self.assertNotIn(forbidden, credential)
        self.assertIn('open("/dev/tty")', source)
        self.assertIn('O_NOFOLLOW | libc::O_CLOEXEC', source)
        self.assertIn('generate_confirmed', source)
        self.assertIn('"luma-offline-admin-recovery-v1\\0"', source)
        self.assertIn('CRYPTO_memcmp(left.as_ptr().cast()', source)
        self.assertIn('let mut preimage = PrivateBuffer::new', source)

    def test_installer_confirms_before_destructive_partitioning_and_persists_only_verifier(self):
        installer = (ROOT / 'rust/luma-platform/src/platform.rs').read_text().split('pub fn install(')[1]
        self.assertLess(installer.index('Credential::generate_confirmed()?'), installer.index('"--zap-all"'))
        self.assertIn('principal::initialize_with_recovery(', installer)
        self.assertIn('drop(admin_recovery);', installer)
        principal = (ROOT / 'rust/luma-platform/src/principal.rs').read_text().split('#[cfg(test)]\nmod tests')[0]
        self.assertIn('admin_recovery: Option<crate::admin_recovery::Verifier>', principal)
        self.assertIn('skip_serializing_if = "Option::is_none"', principal)
        self.assertIn('installer recovery verifier must start at generation one', principal)

    def test_recovery_is_private_live_proof_not_pam_or_wire_command(self):
        governance = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text().split('#[cfg(test)]\nmod tests')[0]
        self.assertIn('recovery: Option<&RecoveryAttempt', governance)
        self.assertIn('command == &attempt.command', governance)
        self.assertIn('snapshot.head == attempt.head', governance)
        self.assertIn('snapshot.clock.elapsed_since(attempt.clock.get())?', governance)
        self.assertIn('final_snapshot.clock.elapsed_since(attempt.clock.get())?', governance)
        proof = governance.split("struct RecoveryAttempt<'a>")[1].split('pub fn recover_admin')[0]
        self.assertIn('ProtectedOperation', proof)
        self.assertIn('registry.current()?', proof)
        self.assertIn('self.verifier.verify(self.credential)?', proof)
        self.assertIn('if reviewed.is_some()', proof)
        self.assertIn('self.lifetime.close()', proof)
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text().split('#[cfg(test)]\nmod tests')[0]
        self.assertIn('CatalogCommand::RecoverAdmin', service)
        self.assertNotIn('Credential::read', service)

    def test_catalog_has_no_unenrolled_recovery_fallback(self):
        roles = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text().split('#[cfg(test)]\nmod tests')[0]
        recovery = roles.split('Command::RecoverAdmin')[1].split('Command::RotateAdmin')[0]
        for marker in ('explicit principal adoption required', 'expected_recovery_generation',
                       'verifier.successor(replacement)?', 'expected_generation', 'checked_add(1)',
                       'self.admin_recovery = Some(replacement.clone())'):
            self.assertIn(marker, recovery)
        self.assertIn('no root or TPM-owner fallback', roles)


if __name__ == '__main__':
    unittest.main()
