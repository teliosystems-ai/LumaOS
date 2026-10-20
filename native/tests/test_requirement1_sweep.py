import importlib.util
import json
import os
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'requirement1_sweep', Path(__file__).with_name('requirement1_sweep.py'))
SWEEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SWEEP)


class SweepExecutionTests(unittest.TestCase):
    def test_actual_cargo_build_scripts_cannot_cross_source_cuts_with_older_mtimes(self):
        with tempfile.TemporaryDirectory(prefix='luma-cargo-source-cache-') as temporary:
            root = Path(temporary)
            project = root / 'project'
            (project / 'src').mkdir(parents=True)
            (project / 'Cargo.toml').write_text('[package]\nname="luma-cache-source-fixture"\nversion="0.0.0"\nedition="2021"\n')
            (project / 'src/main.rs').write_text('include!(concat!(env!("OUT_DIR"),"/marker.rs")); fn main(){println!("{}",MARKER);}\n')
            def run(marker):
                # JSON quoting is also a valid Rust string for these fixed ASCII
                # inputs; no shell or external dependency participates.
                source = 'fn main(){std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("marker.rs"), ' + json.dumps('pub const MARKER: &str = "' + marker + '";') + ').unwrap();println!("cargo:rerun-if-changed=build.rs");}\n'
                (project / 'build.rs').write_text(source)
                os.utime(project / 'build.rs', (1, 1))
                identity = hashlib.sha256(source.encode()).hexdigest()
                target = root / Path(SWEEP.source_target(identity)).relative_to('/cache')
                completed = subprocess.run(['cargo', 'run', '--offline', '--quiet', '--target-dir', str(target)],
                    cwd=project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, 'CARGO_INCREMENTAL': '0'}, timeout=60, check=True)
                self.assertEqual(completed.stdout, (marker + '\n').encode())
                return target
            first = run('first')
            later = run('later')
            self.assertNotEqual(first, later)
            self.assertEqual(run('first'), first)

    def test_cargo_targets_are_separate_for_every_exact_source_cut(self):
        first, later = '1' * 64, '2' * 64
        self.assertEqual(SWEEP.source_target(first), '/cache/target-by-source/' + first)
        self.assertNotEqual(SWEEP.source_target(first), SWEEP.source_target(later))
        self.assertEqual(SWEEP.source_target(first), SWEEP.source_target(first))
        for invalid in ('', first.upper().replace('1', 'A'), '0' * 63, '../target', None):
            with self.assertRaises(ValueError):
                SWEEP.source_target(invalid)

    def test_apparmor_cases_parse_each_shipped_profile_without_loading_or_cache(self):
        repository = Path(__file__).resolve().parents[2]
        cases = SWEEP.apparmor_cases(repository)
        profiles = sorted((repository / 'native/image/overlay/etc/apparmor.d').glob('luma-*'))
        self.assertEqual(len(cases), len(profiles))
        self.assertGreater(len(cases), 0)
        for (name, command, directory, timeout), profile in zip(cases, profiles):
            self.assertEqual(name, 'apparmor-parse-' + profile.name)
            self.assertEqual(command, ['/usr/sbin/apparmor_parser', '-Q', '-K',
                                       '-j1', '--max-jobs', '1', str(profile)])
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

    def test_expanded_profile_group_is_bounded_and_never_ignores_extra_entries(self):
        with tempfile.TemporaryDirectory() as name:
            repository = Path(name)
            profiles = repository / 'native/image/overlay/etc/apparmor.d'
            profiles.mkdir(parents=True)
            for index in range(SWEEP.MAX_APPARMOR_PROFILES):
                (profiles / ('luma-fixture-' + str(index))).write_text('inert parser input')
            self.assertEqual(len(SWEEP.apparmor_cases(repository)), SWEEP.MAX_APPARMOR_PROFILES)
            extra = profiles / 'luma-extra'
            extra.touch()
            with self.assertRaises(ValueError):
                SWEEP.apparmor_cases(repository)
            extra.unlink()
            (profiles / 'luma-fixture-0').unlink()
            (profiles / 'luma-fixture-0').symlink_to(profiles / 'luma-fixture-1')
            with self.assertRaises(ValueError):
                SWEEP.apparmor_cases(repository)

    def test_content_tpm_requires_all_real_scenarios_without_qualification_claims(self):
        from content_checkpoint_integration import CASE, MODES
        record = {'schema_version': 1, 'status': 'CONTENT_CHECKPOINT_SOFTWARE_TPM_PASSED',
                  'physical_tpm_used': False, 'physical_qualification': False,
                  'production_publication_enabled': False,
                  'cases': [{'test': CASE, 'passed': True, 'transport': 'disposable-swtpm',
                             'content_scenario': mode} for mode in MODES]}
        text = json.dumps(record) + '\n'
        self.assertEqual(SWEEP.executed_tests('content-software-tpm', text),
                         {'passed': 3, 'failed': 0, 'skipped': 0})
        for invalid in ('', text + text, text.replace('true', 'false'),
                        text.replace('lost-parent', 'normal'),
                        text.replace('"physical_tpm_used": false', '"physical_tpm_used": true'),
                        json.dumps({**record, 'cases': record['cases'][:2]})):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('content-software-tpm', invalid)

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

    def test_actual_content_cli_lane_requires_nonempty_unskipped_execution(self):
        text = 'Ran 9 tests in 0.1s\n\nOK\n'
        self.assertEqual(SWEEP.executed_tests('content-contract-cli', text)['passed'], 9)
        for invalid in ('', text.replace('9 tests', '0 tests'), text + text,
                        text.replace('OK', 'OK (skipped=1)'),
                        text.replace('OK', 'OK (expected failures=1)')):
            with self.assertRaises(ValueError):
                SWEEP.executed_tests('content-contract-cli', invalid)
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
