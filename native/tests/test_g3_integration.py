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

    def test_governed_content_dispatch_is_confined_but_worker_is_not_a_client_command(self):
        main = (RUST / 'main.rs').read_text()
        allowed = main.split('if confined_client\n', 1)[1].split('if confined_client {', 1)[0]
        for command in ('content-owned-inspection-review', 'content-owned-review', 'content-owned-apply'):
            self.assertIn('"' + command + '"', allowed)
        self.assertNotIn('content-resource-worker', allowed)
        self.assertIn('=> content_governed::command(&args)', main)
        manifest = (ROOT / 'rust/luma-platform/Cargo.toml').read_text()
        self.assertIn('luma-content-store = { path = "../luma-content-store" }', manifest)
        governed = (RUST / 'content_governed.rs').read_text()
        self.assertIn('crate::platform::require_laboratory_image()?;', governed)
        self.assertIn('crate::admin_governance::with_grants', governed)
        self.assertIn('guard.effect_begin', governed)
        self.assertIn('guard.effect_complete', governed)
        self.assertIn('WorkerLease::acquire_acquisition', governed)
        worker = governed.split('fn worker(', 1)[1].split('fn anonymous(', 1)[0]
        self.assertNotIn('admin_governance::current_principal', worker)

    def test_product_content_namespace_is_fresh_install_only_and_worker_private(self):
        platform = (RUST / 'platform.rs').read_text()
        provision = platform.split('Provision fixed empty owner-domain roots;', 1)[1].split(
            'for (name, mode)', 1)[0]
        self.assertIn('"content-store"', provision)
        policies = ROOT / 'native/image/overlay/etc/apparmor.d'
        client = (policies / 'luma-granted-client').read_text()
        worker = (policies / 'luma-acquisition').read_text()
        self.assertIn('deny /var/lib/luma-os/content-store/** rwklx,', client)
        self.assertNotIn('\n  /var/lib/luma-os/content-store/** rwk,', client)
        self.assertIn('/run/luma-granted-client/requests/*/content.json r,', client)
        self.assertIn('/var/lib/luma-os/content-store/** rwk,', worker)
        self.assertIn('/memfd:luma-content-request r,', worker)
        self.assertIn('/memfd:luma-content-output rw,', worker)
        self.assertIn('/proc/[0-9]*/{stat,status,cgroup,cmdline,limits} r,', worker)
        broker = (policies / 'luma-broker').read_text()
        self.assertIn('/run/luma-granted-client/requests/*/content.json r,', broker)
        self.assertNotIn('/var/lib/luma-os/content-store/** rw', broker)


if __name__ == '__main__':
    unittest.main()
