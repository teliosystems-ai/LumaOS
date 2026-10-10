import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'requirement1_sweep', Path(__file__).with_name('requirement1_sweep.py'))
SWEEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SWEEP)


class SweepExecutionTests(unittest.TestCase):
    def test_additional_rust_lane_requires_actual_execution(self):
        text = ('test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; '
                '50 filtered out; finished in 0.1s\n')
        self.assertEqual(SWEEP.executed_tests('rust-tests-policy_decisions', text)['passed'], 2)
        with self.assertRaises(ValueError):
            SWEEP.executed_tests('rust-tests-policy_decisions', text.replace('2 passed', '0 passed'))

    def test_rust_counts_require_actual_execution_not_zero_matches(self):
        text = ('test result: ok. 3 passed; 0 failed; 2 ignored; 0 measured; '
                '5 filtered out; finished in 0.1s\n')
        self.assertEqual(SWEEP.executed_tests('rust-tests', text),
                         dict(passed=3, failed=0, ignored=2, measured=0, filtered_out=5))
        for invalid in ('', text.replace('3 passed', '0 passed')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('rust-tests', invalid)

    def test_native_counts_preserve_skips_and_refuse_empty_or_ambiguous_results(self):
        text = 'Ran 5 tests in 0.1s\n\nOK (skipped=2)\n'
        self.assertEqual(SWEEP.executed_tests('native-source-tests', text),
                         dict(discovered=5, passed=3, failed=0, skipped=2))
        for invalid in ('', text.replace('5 tests', '0 tests'), text + text,
                        text.replace('OK (skipped=2)', 'unfinished')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('native-source-tests', invalid)


if __name__ == '__main__':
    unittest.main()
