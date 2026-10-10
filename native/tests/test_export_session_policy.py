"""Export-session composition checks; not installed confinement qualification."""
from pathlib import Path
import re
import unittest

RUST = Path(__file__).resolve().parents[2] / 'rust/luma-platform/src'


class ExportSessionPolicyTests(unittest.TestCase):
    def test_fixed_export_window_matches_only_the_closed_payload_routes(self):
        session = (RUST / 'authentication/session.rs').read_text()
        standard = int(re.search(r'const WINDOW_NS: u64 = ([\d_]+);', session)[1].replace('_', ''))
        export = int(re.search(r'const EXPORT_WINDOW_NS: u64 = ([\d_]+);', session)[1].replace('_', ''))
        self.assertEqual(standard, 30 * 1_000_000_000)
        self.assertEqual(export, 1800 * 1_000_000_000)
        launcher = (RUST / 'service/granted_gateway.rs').read_text()
        routes = launcher.split('fn payload_command(', 1)[1].split('\n}', 1)[0]
        self.assertEqual(set(re.findall(r'"([a-z-]+)"', routes)), {
            'artifact-owned-export', 'artifact-governed-export',
            'policy-archive-export', 'workflow-history-export'})
        self.assertIn('PAYLOAD_RUNTIME: Duration = Duration::from_secs(1800)', launcher)
        self.assertIn('"--property=RuntimeMaxSec=60"', launcher)

    def test_only_actual_exports_extend_companion_reads_not_reviews_or_disposition(self):
        for file, verb, usage in (
                ('artifact_catalog/owned_effects.rs', 'artifact-owned-export', 'read'),
                ('policy_decisions/history.rs', 'policy-archive-export', 'read_use'),
                ('workflow_history.rs', 'workflow-history-export', 'read')):
            source = (RUST / file).read_text()
            self.assertRegex(source, r'if (?:args\[0\]|verb) == "' + verb + r'" \{\s*'
                             r'crate::admin_governance::with_export_grant\(')
            self.assertIn('&' + usage + ', operation)', source)
            self.assertIn('crate::admin_governance::with_grant(&args[1], &args[2], &'
                          + usage + ', operation)', source)
            self.assertEqual(source.count('with_export_grant('), 2)
        source = (RUST / 'artifact_catalog.rs').read_text()
        self.assertEqual(source.count('with_export_grant('), 1)
        export = source.split('pub(crate) fn governed_export(')[1].split(
            'pub(crate) fn governed_retain(')[0]
        self.assertIn('with_export_grant(', export)

    def test_fresh_checks_still_bracket_each_export_and_its_completion(self):
        governance = (RUST / 'admin_governance.rs').read_text()
        capture = governance.split('fn capture_with_reader(', 1)[1]
        capture = capture.split('fn require_session_purpose(', 1)[0]
        before, bracket = capture.split('self.session.account.observe(|_| {', 1)
        self.assertNotIn('let final_observation = client.recheck', before)
        self.assertLess(bracket.index('let final_observation = client.recheck'),
                        bracket.index('capture_credential_refusal('))
        self.assertLess(bracket.index('capture_credential_refusal('),
                        bracket.index('Ok(GrantCapture {'))
        self.assertIn('observation: final_observation', bracket)
        self.assertLess(bracket.index('})?;'), bracket.index('client.project_after_checks('))
        projected = bracket.split('client.project_after_checks(', 1)[1]
        self.assertIn('self.session.account.check_projection(clock)?', projected)
        self.assertIn('r.session.account.check_projection(clock)?', projected)
        self.assertLess(projected.index('capture_credential_refusal('),
                        projected.index('Ok(captured)'))
        self.assertIn('self.session.account.same_pins(&r.session.account)', before)
        for file in ('artifact_catalog/owned_effects.rs', 'policy_decisions/history.rs'):
            source = (RUST / file).read_text()
            self.assertRegex(source, r'boundary\.stream_check_with_reader\(reader,\s*&pending\)')
            self.assertIn('boundary.check_with_reader(reader)', source)
            self.assertIn('EffectKind::ArtifactExport', source)
        self.assertIn('boundary.stream_check(&pending)', (RUST / 'artifact_catalog.rs').read_text())
        history = (RUST / 'workflow_history.rs').read_text()
        self.assertIn('boundary.stream_history_owner_with_reader(', history)
        self.assertIn('boundary.check_with_reader(reader)', history)
        self.assertIn('ledger.recheck()', history)
        write = history.split('fn write_checked(', 1)[1].split('fn write_record(', 1)[0]
        self.assertIn('bytes.chunks(32 * 1024)', write)
        self.assertRegex(write, r'check\(\)\?;\s*writer\.write_all\(block\)\?;\s*check\(\)\?;')
        for file in ('artifact_catalog/owned_effects.rs', 'artifact_catalog.rs',
                     'workflow_history.rs'):
            self.assertIn('effect_complete(pending', (RUST / file).read_text())


if __name__ == '__main__':
    unittest.main()
