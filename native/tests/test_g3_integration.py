"""Source routing regressions; behavior lives in Rust and actual CLI fixtures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / 'rust/luma-platform/src'


class G3IntegrationTests(unittest.TestCase):
    def test_owned_search_is_confined_standard_scope_not_extended_export(self):
        main = (RUST / 'main.rs').read_text()
        allowed = main.split('if confined_client\n', 1)[1].split('if confined_client {', 1)[0]
        self.assertIn('"artifact-owned-search"', allowed)
        self.assertIn('Some("artifact-owned-search") if args.len() == 5', main)
        launcher = (RUST / 'service/granted_gateway.rs').read_text()
        self.assertIn('| "artifact-owned-search"', launcher)
        payload = launcher.split('fn payload_command(', 1)[1].split('\n}', 1)[0]
        extended = launcher.split('fn extended_client_command(', 1)[1].split('\n}', 1)[0]
        self.assertNotIn('artifact-owned-search', payload)
        self.assertNotIn('artifact-owned-search', extended)

    def test_owned_search_checks_live_authority_during_private_reads_and_delivery(self):
        source = (RUST / 'artifact_catalog/owned_search.rs').read_text()
        for required in ('gc_cli::subject', 'gc_cli::inspection', 'with_grant', 'gc_cli::check_owner',
                         'domains::open_at_base', 'Some(account.generation)', 'search::search_checked',
                         'bytes.chunks(32 * 1024)', 'output.flush()?'):
            self.assertIn(required, source)
        self.assertNotIn('Catalog::open(', source)
        self.assertNotIn('SessionPurpose::Export', source)

    def test_shared_content_inspection_is_bounded_nonauthoritative_and_packaged(self):
        source = (RUST / 'content_contract.rs').read_text()
        for required in ('MAX_REQUEST', 'take(MAX_REQUEST as u64 + 1)', 'deny_unknown_fields',
                         'luma_content::capture', 'luma_content::reopen', 'luma_content::compare_external_edit'):
            self.assertIn(required, source)
        for flag in ('"owner_authenticated":false', '"authority_returned":false', '"committed":false'):
            self.assertIn(flag, source)
        self.assertNotIn('require_root()', source)
        self.assertNotIn('OpenOptions', source)
        self.assertIn('"luma-content"', (ROOT / 'rust/Cargo.toml').read_text())
        self.assertIn('luma-content = { path = "../luma-content" }',
                      (ROOT / 'rust/luma-platform/Cargo.toml').read_text())

    def test_table_edit_is_an_inert_data_command_not_a_confined_effect(self):
        main = (RUST / 'main.rs').read_text()
        source = (RUST / 'content_contract.rs').read_text()
        self.assertIn('| "content-contract-table-edit"', main)
        self.assertIn('luma_content::table::apply', source)
        self.assertIn('request.edit.canonical_bytes()', source)
        self.assertIn('"request_retained":false', source)
        allowed = main.split('if confined_client\n', 1)[1].split('if confined_client {', 1)[0]
        self.assertNotIn('content-contract-table-edit', allowed)
        launcher = (RUST / 'service/granted_gateway.rs').read_text()
        self.assertNotIn('content-contract-table-edit', launcher)


if __name__ == '__main__':
    unittest.main()
