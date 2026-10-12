import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'requirement1_sweep', Path(__file__).with_name('requirement1_sweep.py'))
SWEEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SWEEP)


class SweepExecutionTests(unittest.TestCase):
    def test_apparmor_cases_parse_each_shipped_profile_without_loading_or_cache(self):
        repository = Path(__file__).resolve().parents[2]
        cases = SWEEP.apparmor_cases(repository)
        profiles = sorted((repository / 'native/image/overlay/etc/apparmor.d').glob('luma-*'))
        self.assertEqual(len(cases), len(profiles))
        self.assertGreater(len(cases), 0)
        for (name, command, directory, timeout), profile in zip(cases, profiles):
            self.assertEqual(name, 'apparmor-parse-' + profile.name)
            self.assertEqual(command, ['/usr/sbin/apparmor_parser', '-Q', '-K', str(profile)])
            self.assertEqual(directory, repository)
            self.assertEqual(timeout, 60)

    def test_full_rust_environment_uses_this_isolated_storage_root(self):
        with patch.dict(os.environ, {'LUMA_STORAGE_TEST_ROOT': '/wrong-root',
                                    'RUSTFLAGS': '-Dunused'}, clear=True):
            environment = SWEEP.fixture_environment(Path('/evidence/sweep'), True)
        self.assertEqual(environment['LUMA_STORAGE_TEST_ROOT'], '/evidence/sweep')
        self.assertEqual(environment['RUSTFLAGS'], '-Dwarnings')
        self.assertEqual(environment['CARGO_INCREMENTAL'], '0')
        self.assertEqual(environment['PYTHONDONTWRITEBYTECODE'], '1')

    def test_model_public_lane_requires_actual_unskipped_crypto_cases(self):
        text = 'Ran 10 tests in 0.1s\n\nOK\n'
        self.assertEqual(SWEEP.executed_tests('model-public-authentication', text)['passed'], 10)
        for invalid in ('', text.replace('10 tests', '0 tests'),
                        text.replace('OK', 'OK (skipped=1)'),
                        text.replace('OK', 'OK (expected failures=1)')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('model-public-authentication', invalid)

    def test_public_trust_lane_requires_actual_unskipped_crypto_cases(self):
        text = 'Ran 13 tests in 0.1s\n\nOK\n'
        self.assertEqual(SWEEP.executed_tests('public-trust-authentication', text)['passed'], 13)
        for invalid in ('', text.replace('13 tests', '0 tests'),
                        text.replace('OK', 'OK (skipped=1)'),
                        text.replace('OK', 'OK (expected failures=1)')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('public-trust-authentication', invalid)
    def test_utc_crypto_lane_requires_nonempty_all_passing_tests(self):
        text = 'Ran 7 tests in 0.1s\n\nOK\n'
        self.assertEqual(SWEEP.executed_tests('utc-release-authentication', text)['passed'], 7)
        for invalid in ('', text.replace('7 tests', '0 tests'),
                        text.replace('OK', 'OK (skipped=1)'),
                        text.replace('OK', 'OK (expected failures=1)')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('utc-release-authentication', invalid)

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
