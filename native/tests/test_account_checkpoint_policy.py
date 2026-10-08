"""Credential-checkpoint composition checks, not installed lifecycle qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AccountCheckpointPolicyTests(unittest.TestCase):
    def test_source_is_fixed_and_inspection_never_accepts_credentials(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        entry = source.split('pub fn checkpoint_accounts(')[1].split('pub fn adopt_principals(')[0]
        for marker in ('crate::require_root()?', 'platform::require_installed()?',
                       'Path::new(crate::principal::REGISTRY)', 'run_control_at('):
            self.assertIn(marker, entry)
        self.assertLess(entry.index('prepare_control('), entry.index('authentication::local('))
        self.assertNotIn('fs::write', entry)
        identity = source.split('fn account_identity(')[1].split('pub fn checkpoint_accounts(')[0]
        self.assertIn('Path::new(crate::principal::IDENTITY)', identity)
        self.assertIn('#[cfg(test)]', identity)
        self.assertIn('!Path::new("/dev/tpm0").exists()', identity)
        self.assertNotIn('std::env::', identity)

    def test_secret_rows_stay_in_locked_buffers_and_only_domain_commitments_escape(self):
        source = (ROOT / 'rust/luma-platform/src/principal.rs').read_text()
        observation = source.split('fn account_file(')[1].split('struct AccountBinding')[0]
        self.assertIn('PrivateBuffer::new', observation)
        commitment = source.split('fn credential_commitment(')[1].split('fn identity(')[0]
        self.assertEqual(commitment.count('self.current_uid()?;'), 2)
        self.assertIn('luma-account-credential-checkpoint-v1', commitment)
        for marker in ('self.installation', 'self.principal.id', 'self.principal.uid', 'self.account_digest'):
            self.assertIn(marker, commitment)
        for forbidden in ('println!', 'Serialize', 'Deserialize', 'fs::write'):
            self.assertNotIn(forbidden, commitment)

    def test_all_original_account_pins_survive_each_authentication_boundary(self):
        source = (ROOT / 'rust/luma-platform/src/admin_governance.rs').read_text()
        engine = source.split('fn execute_catalog_authorized_at<')[1].split('struct RecoveryAttempt')[0]
        self.assertIn('account_checkpoint_at(registry_path, identity_path)?', engine)
        self.assertIn('&observed != command', engine)
        self.assertEqual(engine.count('for account in &account_pins'), 2)
        self.assertIn('context.recheck(&mut authenticate)', engine)
        reader = source.split('fn replay(')[2].split('fn resolve(')[0]
        self.assertRegex(reader, r'catalog\s*\.account_commitments\s*\.get\(principal\)')
        self.assertIn('account.credential_commitment()? != expected', reader)
        self.assertIn('credential_sha256', reader)

    def test_wire_cannot_checkpoint_caller_supplied_hashes(self):
        service = (ROOT / 'rust/luma-platform/src/admin_service.rs').read_text()
        validation = service.split('fn validate(')[1].split('fn handle(')[0]
        self.assertIn('CatalogCommand::CheckpointAccounts', validation)
        self.assertIn('account checkpoints require protected sources', validation)
        main = (ROOT / 'rust/luma-platform/src/main.rs').read_text()
        self.assertIn('Some("admin-accounts-checkpoint")', main)

    def test_legacy_bytes_are_not_rewritten_and_rebinding_has_no_fallback(self):
        source = (ROOT / 'rust/luma-platform/src/admin_roles.rs').read_text()
        self.assertIn('#[serde(skip_serializing_if = "BTreeMap::is_empty")]\n    pub account_commitments', source)
        checkpoint = source.split('Command::CheckpointAccounts { commitments } =>')[1].split('Command::RecoverAdmin')[0]
        self.assertIn('explicit principal adoption required', checkpoint)
        self.assertIn('if &self.account_commitments == commitments', checkpoint)
        self.assertIn('lifecycle reconciliation required', checkpoint)
        self.assertNotIn('write_atomic', checkpoint)
        self.assertNotIn('remove_file', checkpoint)


if __name__ == '__main__':
    unittest.main()
