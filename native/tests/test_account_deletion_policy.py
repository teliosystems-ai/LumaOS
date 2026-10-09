"""Deletion source-composition checks, not installed security qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AccountDeletionPolicyTests(unittest.TestCase):
    def test_general_socket_transport_and_service_mount_remain_read_only(self):
        source = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text()
        validation = source.split('fn validate(')[1].split('fn handle(')[0]
        for command in ('PrepareAccountDeletion', 'PermitAccountDeletion', 'CompleteAccountDeletion'):
            self.assertIn('CatalogCommand::' + command, validation)
        unit = (ROOT / 'native/image/overlay/etc/systemd/system/luma-admin.service').read_text()
        writable = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
        self.assertNotIn('/var/lib/luma-os/identity', writable)
        self.assertIn('ProtectSystem=strict', unit)

    def test_local_dispatch_is_owned_scoped_and_rechecks_current_authority(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        attempt = source.split('struct DeletionAttempt')[1].split('pub fn account_deletion_command(')[0]
        for marker in ('PrincipalPurpose::AdminCatalog', 'candidate == transaction',
                       'session.observe_store(', 'Command::PermitAccountDeletion',
                       'Guard::retained(', 'self.guard.publish(', 'self.session.fenced.get()',
                       'current.head != self.snapshot.head', 'context.writer(&self.catalog)',
                       'self.session.account.identity()', 'self.session.close()'):
            self.assertIn(marker, attempt)
        entry = source.split('pub fn account_deletion_command(')[1].split('pub fn adopt_principals(')[0]
        self.assertLess(entry.index('prepare_control('), entry.index('authentication::local('))
        for marker in ('Path::new(crate::principal::REGISTRY)',
                       'Path::new(crate::principal::IDENTITY)', 'prepared.issue(',
                       'DeletionAttempt::prepare(', 'run_control_at('):
            self.assertIn(marker, entry)
        for forbidden in ('std::env::', 'Command::new', 'fs::write', 'password'):
            self.assertNotIn(forbidden, entry)

    def test_four_file_engine_retains_private_evidence_and_refuses_unsafe_recovery(self):
        source = (ROOT / 'rust/luma-platform/src/account_deletion.rs').read_text().split('#[cfg(test)]')[0]
        for marker in ('["shadow", "gshadow", "group", "passwd"]', 'PrivateBuffer::new',
                       'LOCK_EX | libc::LOCK_NB', 'O_NOFOLLOW', 'O_CLOEXEC',
                       'libc::SYS_renameat2', 'libc::RENAME_NOREPLACE', 'libc::renameat(',
                       'retained >= 128', 'index != self.published', 'authorize()?',
                       'self.directory.sync_all()?', 'stage.sync_all()?',
                       'shared or mismatched private group', 'unapproved deletion publication order'):
            self.assertIn(marker, source)
        for forbidden in ('println!', 'eprintln!', 'fs::read(', 'read_to_string',
                          'remove_file', 'remove_dir', 'truncate(', 'Command::new', 'std::env::'):
            self.assertNotIn(forbidden, source)

    def test_catalog_fences_target_and_preserves_reserved_tombstones(self):
        source = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text()
        reducer = source.split('match command {')[1]
        prepare = reducer.split('Command::PrepareAccountDeletion')[1].split('Command::PermitAccountDeletion')[0]
        complete = reducer.split('Command::CompleteAccountDeletion')[1].split('Command::PrepareAccountLock')[0]
        self.assertIn('enabled: false', prepare)
        self.assertNotIn('deleted_principals.insert', prepare)
        self.assertRegex(complete, r'deleted_principals\s*\.insert\(')
        self.assertNotIn('enabled: true', complete)
        self.assertNotIn('principal_registry =', complete)
        self.assertNotIn('account_commitments.insert', complete)
        self.assertGreaterEqual(source.count('self.deleted_principals.contains('), 3)


if __name__ == '__main__':
    unittest.main()
