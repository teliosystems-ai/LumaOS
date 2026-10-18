"""Closed software/source checks, not proof of native PAM/TPM confinement."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "rust/luma-platform/src"


class ContentCustodyBootstrap(unittest.TestCase):
    def test_original_statement_binds_hash_and_installation_not_matching_mutable_headers(self):
        source = (SRC / "content_custody/genesis.rs").read_text()
        compact = ''.join(source.split())
        for required in ('deny_unknown_fields', 'genesis.json',
                         'statement.installation!=installation',
                         'protected!=genesis',
                         'luma-content-explicit-empty-genesis-v1',
                         'statement.domains.is_empty()',
                         'serde_json::to_vec(&value)?!=bytes'):
            self.assertIn(''.join(required.split()), compact)
        self.assertIn('different retained genesis proof must be preserved', source)

    def test_bootstrap_requires_read_then_exact_original_admin_recovery_and_real_initial_nv(self):
        source = (SRC / "content_custody/bootstrap.rs").read_text()
        command = source[source.index('pub(crate) fn command'):]
        compact = ''.join(command.split())
        for required in ('with_grant', 'guard.require_admin()',
                         'EmptyNamespace::capture', 'Action::RecoverResource',
                         'retain_genesis_statement', 'ContentAnchor::installed()',
                         'anchor.read()?!=tpm::extend_value([0;32],genesis)',
                         'initialize_empty', 'guard.effect_complete'):
            self.assertIn(''.join(required.split()), compact)
        self.assertLess(compact.index('ifinspect{'), compact.index('retain_genesis_statement'))
        self.assertLess(compact.index('retain_genesis_statement'), compact.index('ContentAnchor::installed()'))
        self.assertLess(compact.index('anchor.read()?!=tpm::extend_value'), compact.index('initialize_empty'))
        self.assertIn('"NV_authenticated":false', source)
        self.assertIn('"NV_authenticated":true', source)
        self.assertIn('"TPM_extended":false', source)
        self.assertNotIn('|| Ok(())', command)

    def test_original_admin_route_is_reachable_without_generic_shell_or_granted_client_bypass(self):
        main = (SRC / "main.rs").read_text()
        wrapper = (ROOT / "native/image/overlay/usr/bin/luma-admin-control").read_text()
        for command in ('content-custody-bootstrap-proposal',
                        'content-custody-bootstrap-review', 'content-custody-bootstrap'):
            self.assertIn(command, main)
            self.assertIn(command, wrapper)
        self.assertIn('custody::bootstrap_command(&args)', main)
        source = (SRC / 'content_custody.rs').read_text()
        compact = ''.join(source.split())
        self.assertIn('genesis::validate(&proof,&installation,genesis)?', compact)
        self.assertIn('self.files.read("genesis.json",check)?!=*expected', compact)


if __name__ == '__main__':
    unittest.main()
