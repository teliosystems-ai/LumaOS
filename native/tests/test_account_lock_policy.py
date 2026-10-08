"""Account-lock composition checks, not installed security qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AccountLockPolicyTests(unittest.TestCase):
    def test_fixed_local_ceremony_prepares_before_pam_and_accepts_no_secret(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        entry = source.split('pub fn account_lock_command(')[1].split('pub fn adopt_principals(')[0]
        for marker in ('crate::require_root()?', 'platform::require_installed()?',
                       'Path::new(crate::principal::REGISTRY)', 'Path::new(crate::principal::IDENTITY)',
                       'run_control_at(', 'Guard::prepare('):
            self.assertIn(marker, entry)
        self.assertLess(entry.index('prepare_control('), entry.index('authentication::local('))
        for forbidden in ('std::env::', 'password', 'fs::write', 'Command::new'):
            self.assertNotIn(forbidden, entry)

    def test_socket_service_has_no_account_mutation_transport(self):
        source = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text()
        validation = source.split('fn validate(')[1].split('fn handle(')[0]
        for command in ('PrepareAccountLock', 'PermitAccountPublication', 'CompleteAccountLock'):
            self.assertIn('CatalogCommand::' + command, validation)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-admin.service').read_text()
        writable = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        self.assertNotIn('/var/lib/luma-os/identity', writable)
        self.assertIn('ProtectSystem=strict', unit)

    def test_file_engine_has_no_plaintext_diagnostics_or_pageable_shadow(self):
        source = (ROOT / 'rust/luma-platform/src/account_transition.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('PrivateBuffer::new', 'LOCK_EX | libc::LOCK_NB', 'O_NOFOLLOW',
                       'O_CLOEXEC', 'libc::renameat(', 'source_recheck()', 'file.sync_all()?',
                       'self.directory.sync_all()?', 'stage_directory.sync_all()?'):
            self.assertIn(marker, source)
        for forbidden in ('println!', 'eprintln!', 'fs::read(', 'read_to_string',
                          'remove_file', 'truncate(', 'Command::new', 'std::env::'):
            self.assertNotIn(forbidden, source)

    def test_publication_requires_the_owned_continuation_and_fresh_checkpoint(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        publication = source.split('The ordinary account projection must finish')[1].split('impl Drop for CatalogAttempt')[0]
        self.assertRegex(publication, r'events\s*\.iter\(\)')
        for marker in ('event.command == self.command', 'context.writer(&catalog)',
                       'Phase::PublicationPermitted', 'guard.publish(||', 'self.authenticate()?',
                       'current.head != snapshot.head', 'context.recheck('):
            self.assertIn(marker, publication)
        engine = source.split('fn execute_catalog_authorized_at<')[1].split('enum AccountBoundary')[0]
        self.assertIn('intent.transaction != request', engine)
        self.assertEqual(engine.count('boundary.recheck()?'), 2)
        self.assertLess(engine.index('approved != digest'), engine.index('guard.stage()?'))

    def test_pending_transition_is_not_credential_or_principal_enable_authority(self):
        source = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text()
        reducer = source.split('match command {')[1].split('Command::CheckpointAccounts')[0]
        prepare = reducer.split('Command::PrepareAccountLock')[1].split('Command::PermitAccountPublication')[0]
        self.assertIn('enabled: false', prepare)
        self.assertNotIn('account_commitments.insert', prepare)
        permit = reducer.split('Command::PermitAccountPublication')[1].split('Command::CompleteAccountLock')[0]
        self.assertNotIn('account_commitments.insert', permit)
        complete = reducer.split('Command::CompleteAccountLock')[1]
        self.assertIn('credential_after', complete)
        self.assertIn('!current.intent.locked', complete)
        self.assertIn('pending account transaction fences principal changes', source)


if __name__ == '__main__':
    unittest.main()
