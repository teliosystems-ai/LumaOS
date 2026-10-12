"""Orchestration regressions; synthetic transcripts are not qualification."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('g2_fixture_sweep', Path(__file__).with_name('g2_fixture_sweep.py'))
SWEEP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SWEEP)
ROOT = Path(__file__).resolve().parents[2]


def rust(name, passed=1, ignored=0, failed=0):
    return ('running 1 test\ntest ' + name + ' ... ok\n'
            'test result: ok. %d passed; %d failed; %d ignored; 0 measured; 100 filtered out;\n'
            % (passed, failed, ignored))


class FixtureSweepTests(unittest.TestCase):
    def test_sparse_fixture_extent_and_transcript_limits_are_separate(self):
        with patch.object(SWEEP.resource, 'setrlimit') as limits:
            SWEEP.limited_child()
            limits.assert_any_call(SWEEP.resource.RLIMIT_FSIZE, (SWEEP.MAX_LOG, SWEEP.MAX_LOG))
            limits.reset_mock()
            SWEEP.fixture_child()
            limits.assert_any_call(SWEEP.resource.RLIMIT_FSIZE,
                                   (SWEEP.MAX_FIXTURE_FILE, SWEEP.MAX_FIXTURE_FILE))
        self.assertGreater(SWEEP.MAX_FIXTURE_FILE, 3 * 1024 * 1024 * 1024)

    def test_successful_child_with_oversized_transcript_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(SWEEP, 'MAX_LOG', 64):
            with self.assertRaises(RuntimeError):
                SWEEP.execute([sys.executable, '-c', 'print("x" * 128)'], ROOT,
                              dict(os.environ), Path(folder), 0, 5)
            self.assertGreater((Path(folder) / 'command-000.log').stat().st_size, 64)

    def test_every_current_ignored_entry_has_precise_fixture_or_child_owner(self):
        inventory = SWEEP.ignored_inventory(ROOT)
        self.assertEqual(len(inventory), 42)
        self.assertEqual(len(SWEEP.CHILDREN), 7)
        external = set(inventory) - set(SWEEP.CHILDREN)
        self.assertEqual(len(external), 35)
        for name in external:
            self.assertTrue(any(name in lane['required'] for lane in SWEEP.LANES.values()))
        for child, (lane, parent) in SWEEP.CHILDREN.items():
            self.assertIn(parent, SWEEP.LANES[lane]['required'])
            self.assertNotIn(child, SWEEP.LANES[lane]['required'])

    def test_positive_named_kernel_execution_records_children_without_double_count(self):
        text = ''.join(rust(name) for name in SWEEP.KERNEL)
        evidence = SWEEP.verify_execution('kernel', [text], {})
        self.assertEqual(set(evidence['named_executions']), set(SWEEP.KERNEL))
        self.assertTrue(all(count == 1 for count in evidence['named_executions'].values()))
        self.assertEqual(len(evidence['owned_children']), 3)
        self.assertTrue(all(not item['directly_counted'] for item in evidence['owned_children']))

    def test_missing_empty_failed_ignored_or_unrecognized_rust_does_not_qualify(self):
        text = ''.join(rust(name) for name in SWEEP.KERNEL)
        candidates = ('', text.replace(SWEEP.KERNEL[0], 'unrelated::tests::entry'),
                      text.replace('1 passed', '0 passed'), text.replace('0 failed', '1 failed'),
                      text.replace('0 ignored', '1 ignored'), text.replace('0 measured', '1 measured'))
        for candidate in candidates:
            with self.subTest(candidate=candidate[:80]):
                with self.assertRaises(ValueError):
                    SWEEP.verify_execution('kernel', [candidate], {})

    def test_model_internal_entry_is_explicit_not_a_skipped_qualifying_test(self):
        names = SWEEP.LANES['model-process']['required']
        text = rust(names[0]) + rust(names[1], passed=20, ignored=1)
        evidence = SWEEP.verify_execution('model-process', [text], {})
        self.assertEqual(len(evidence['owned_children']), 2)
        with self.assertRaises(ValueError):
            SWEEP.verify_execution('model-process', [text.replace('1 ignored', '2 ignored')], {})

    def test_selected_python_suite_never_accepts_skips_or_expected_failures(self):
        valid = 'Ran 13 tests in 1.0s\n\nOK\n'
        SWEEP.verify_execution('public-trust', [valid], {})
        SWEEP.verify_execution('model-public', [valid], {})
        for candidate in ('', valid.replace('13 tests', '0 tests'), valid + valid,
                          valid.replace('OK', 'OK (skipped=1)'),
                          valid.replace('OK', 'OK (expected failures=1)'),
                          valid.replace('OK', 'FAILED (errors=1)')):
            with self.assertRaises(ValueError):
                SWEEP.verify_execution('public-trust', [candidate], {})
            with self.assertRaises(ValueError):
                SWEEP.verify_execution('model-public', [candidate], {})

    def test_fixture_markers_are_not_accepted_instead_of_required_real_tests(self):
        lane = SWEEP.LANES['principal-pam']
        with self.assertRaises(ValueError):
            SWEEP.verify_execution('principal-pam', [lane['marker']], {})
        SWEEP.verify_execution('principal-pam', [rust(lane['required'][0]) + lane['marker']], {})

    def test_transport_zero_cases_refuses_despite_completed_marker(self):
        for lane in ('resource-history-cli', 'model-chat-cli'):
            marker = SWEEP.LANES[lane]['marker']
            with self.assertRaises(ValueError):
                SWEEP.verify_execution(lane, [marker + '0'], {})
            SWEEP.verify_execution(lane, [marker + '2 synthetic_authority=true'], {})

    def test_actual_custody_cases_require_every_exact_marker_and_named_execution(self):
        lane = SWEEP.LANES['pam-catalog']
        named = ''.join(rust(name) for name in lane['required'])
        markers = '\n'.join(lane['required_markers']) + '\n' + lane['marker']
        SWEEP.verify_execution('pam-catalog', [named + markers], {})
        for marker in lane['required_markers']:
            with self.subTest(marker=marker):
                with self.assertRaises(ValueError):
                    SWEEP.verify_execution('pam-catalog', [named + markers.replace(marker, '')], {})
                with self.assertRaises(ValueError):
                    SWEEP.verify_execution('pam-catalog', [named + markers.replace(marker, 'not-run:' + marker)], {})
        with self.assertRaises(ValueError):
            SWEEP.verify_execution('pam-catalog', [markers], {})

    def test_private_mount_authority_is_only_closed_optional_lanes(self):
        selected = [name for name, lane in SWEEP.LANES.items() if lane.get('mounts')]
        self.assertEqual(selected, ['storage', 'recovery-enospc'])
        self.assertNotIn('SYS_ADMIN', SWEEP.CAPS)
        self.assertNotIn('SYS_TIME', SWEEP.CAPS)
        self.assertTrue(SWEEP.LANES['utc-upstream-units']['capless'])

    def test_actual_pam_atomic_registry_publication_uses_same_d_backed_layer(self):
        temporary = Path('/mnt/luma-build/work/test/temporary')
        for lane in SWEEP.LANES:
            expected = [] if lane == 'pam-catalog' else [
                '--mount', f'type=bind,source={temporary},target=/tmp']
            self.assertEqual(SWEEP.temporary_mounts(lane, temporary), expected)
        with self.assertRaises(ValueError):
            SWEEP.temporary_mounts('unknown', temporary)

    def test_bounded_regular_read_refuses_symlink_hardlink_and_oversized(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            file = root / 'file'
            file.write_bytes(b'ab')
            self.assertEqual(SWEEP.bounded(file, 2), b'ab')
            with self.assertRaises(ValueError):
                SWEEP.bounded(file, 1)
            link = root / 'link'
            link.symlink_to(file)
            with self.assertRaises(OSError):
                SWEEP.bounded(link, 2)
            hard = root / 'hard'
            hard.hardlink_to(file)
            with self.assertRaises(ValueError):
                SWEEP.bounded(file, 2)

    def test_new_ignored_entries_cannot_silently_escape_stage_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'rust/luma-platform/src/new.rs'
            path.parent.mkdir(parents=True)
            path.write_text('#[ignore = "new fixture"]\nfn new_boundary() {}\n')
            with self.assertRaises(ValueError):
                SWEEP.ignored_inventory(root)

    def test_manifest_requires_every_executable_input_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for directory in ('rust', 'native/tests', 'native/image'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            path = root / 'native/tests/case.py'
            path.write_bytes(b'print(1)\n')
            manifest = root / 'build-inputs.json'
            manifest.write_text(json.dumps({'schema_version': 1, 'files': [{
                'path': 'native/tests/case.py', 'bytes': path.stat().st_size,
                'sha256': SWEEP.digest(path)}]}))
            SWEEP.verify_source(root)
            (root / 'native/tests/unrecorded.py').write_text('print(2)\n')
            with self.assertRaises(ValueError):
                SWEEP.verify_source(root)
            (root / 'native/tests/unrecorded.py').unlink()
            path.write_bytes(b'print(3)\n')
            with self.assertRaises(ValueError):
                SWEEP.verify_source(root)


if __name__ == '__main__':
    unittest.main()
