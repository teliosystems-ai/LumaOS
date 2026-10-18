"""Closed disposable content-checkpoint fixture selection and result evidence."""
import unittest

from content_checkpoint_integration import CASE, MODES
from resource_checkpoint_integration import require_single_execution


class ContentCheckpointDriverTests(unittest.TestCase):
    def test_all_three_scenarios_share_the_existing_real_three_authority_entry(self):
        self.assertEqual(CASE, 'tpm::tests::emulator_admin_and_resource_authorities_have_independent_handles_and_secrets')
        self.assertEqual(MODES, ('normal', 'lost-publication', 'lost-parent'))
        self.assertEqual(len(set(MODES)), 3)

    def test_execution_evidence_cannot_substitute_skipped_or_empty_tests(self):
        output = ('running 1 test\n'
                  f'test {CASE} ... ok\n'
                  'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 1.00s\n')
        require_single_execution(CASE, output)
        for altered in (
            output.replace('running 1 test', 'running 0 tests'),
            output.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored'),
            output.replace(CASE, 'unrelated::fixture'),
            output + output,
        ):
            with self.assertRaises(RuntimeError):
                require_single_execution(CASE, altered)


if __name__ == '__main__':
    unittest.main()
