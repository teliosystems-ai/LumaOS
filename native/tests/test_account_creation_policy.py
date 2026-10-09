"""Creation source composition, not installed or physical qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AccountCreationPolicyTests(unittest.TestCase):
    def test_socket_rejects_creation_and_has_no_identity_or_home_write_mount(self):
        source = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text()
        validation = source.split('fn validate(')[1].split('fn handle(')[0]
        for command in ('PrepareAccountCreation', 'PermitAccountCreation', 'CompleteAccountCreation'):
            self.assertIn('CatalogCommand::' + command, validation)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-admin.service').read_text()
        writable = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        for path in ('/var/lib/luma-os/identity', '/var/lib/luma-os/principals', '/var/home'):
            self.assertNotIn(path, writable)
        self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('CapabilityBoundingSet=CAP_CHOWN', unit)
        profile = (ROOT / 'native/image/overlay/etc/apparmor.d/luma-admin').read_text()
        self.assertIn('capability dac_override,', profile)
        self.assertIn('/var/home/*/.luma-creation.json r,', profile)

    def test_dispatch_requires_owned_scoped_session_and_closes_it(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        attempt = source.split('struct CreationAttempt')[1].split('pub fn account_creation_command(')[0]
        for marker in ('PrincipalPurpose::AdminCatalog', 'candidate == transaction',
                       'session.observe_store(', 'Command::PermitAccountCreation',
                       'Guard::retained(', 'self.guard.publish(', 'self.session.fenced.get()',
                       'current.head != self.snapshot.head', 'context.writer(&self.catalog)',
                       'self.session.account.identity()', 'self.session.close()'):
            self.assertIn(marker, attempt)
        entry = source.split('pub fn account_creation_command(')[1].split('pub fn account_password_command(')[0]
        for marker in ('Password::local_confirmed()', 'retained_intent(', 'prepared.issue(',
                       'CreationAttempt::prepare(', 'creation_proposal(', 'CatalogAttempt::prepare('):
            self.assertIn(marker, entry)
        for forbidden in ('std::env::', 'Command::new', 'fs::write', 'password.as_bytes'):
            self.assertNotIn(forbidden, entry)

    def test_creation_never_uses_host_time_or_overwrites_conflicting_evidence(self):
        source = (ROOT / 'rust/luma-platform/src/account_creation.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('PrivateBuffer::new', 'libc::LOCK_EX | libc::LOCK_NB', 'libc::RENAME_NOREPLACE',
                       'libc::renameat(', 'authorize()?', 'index != self.published',
                       'conflicting interrupted creation dispatch', 'credential_after',
                       'b":0:0:99999:7:::\\n"', 'append_account('):
            self.assertIn(marker, source)
        for forbidden in ('SystemTime', 'chrono::', 'println!', 'eprintln!', 'remove_file',
                          'remove_dir', 'truncate(', 'Command::new', 'std::env::'):
            self.assertNotIn(forbidden, source)

    def test_catalog_preserves_original_identity_and_fences_unaged_activation(self):
        source = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text()
        reducer = source.split('match command {')[1]
        creation = reducer.split('Command::PrepareAccountCreation')[1].split('Command::PrepareAccountDeletion')[0]
        self.assertNotIn('self.principal_registry =', creation)
        self.assertNotIn('enabled: true', creation)
        for marker in ('current_registry', 'needs_password_aging', 'credential_after'):
            self.assertIn(marker, creation)
        self.assertGreaterEqual(source.count('self.needs_password_aging.contains('), 2)


if __name__ == '__main__':
    unittest.main()
