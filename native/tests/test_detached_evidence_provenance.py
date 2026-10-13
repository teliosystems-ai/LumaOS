"""Synthetic Git provenance fixtures; no product or historical test-pass claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('detached_evidence_check', ROOT / 'scripts/check.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DetachedEvidenceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='luma-detached-source-')
        self.root = Path(self.directory.name)
        self.patch = mock.patch.object(CHECK, 'ROOT', self.root)
        self.patch.start()
        self.git('init', '-q')
        self.put('src/package.py', 'VALUE = 1\n')
        self.put('schemas/profile.json', '{}\n')
        self.put('tests/test_boundary.py', 'class Boundary:\n    def test_one(self):\n        pass\n')
        requirements = [{'id': 'G2-' + str(i), 'closure_gate': 'G2',
                         'implementation_status': 'in_progress' if i < 20 else 'not_started',
                         'latest_evidence': {'state': 'not_run'}} for i in range(34)]
        requirements += [{'id': 'Other-' + str(i), 'closure_gate': 'G1'} for i in range(254)]
        self.put('requirements/registry.json', json.dumps({'requirements': requirements}))
        self.paths = sorted(['src/package.py', 'schemas/profile.json', 'tests/test_boundary.py',
                             'requirements/registry.json', 'RELEASE_MANIFEST.json'])
        self.put('RELEASE_MANIFEST.json', json.dumps({'release_files': self.paths}))
        self.git('add', '--all')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Synthetic recorded snapshot')
        self.commit = self.git('rev-parse', 'HEAD').strip()

    def tearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    def git(self, *arguments):
        return subprocess.run(['git', '--no-pager', '-c', 'commit.gpgsign=false',
                               '-c', 'core.hooksPath=' + str(self.root / 'disabled-hooks'),
                               *arguments], cwd=self.root,
                              check=True, capture_output=True, text=True, timeout=10).stdout

    def put(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def counts(self, commit=None):
        return CHECK.historical_source_counts(commit or self.commit, ('test_boundary.py',))

    def test_counts_come_from_recorded_blobs_not_newer_head_or_uncommitted_files(self):
        before, paths = self.counts()
        self.assertEqual(paths, self.paths)
        self.assertEqual(before['python_modules_compiled'], 1)
        self.assertEqual(before['unit_tests_run_per_lane'], 1)
        self.assertEqual(before['g2_requirements_in_progress'], 20)
        self.assertEqual(before['g2_requirements_not_started'], 14)
        self.put('src/new_module.py', 'NEW = 2\n')
        self.put('src/package.py', 'VALUE = 3\n')
        self.git('add', '--all')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Different current source')
        self.put('tests/test_boundary.py', 'Uncommitted replacement\n')
        self.assertEqual(self.counts(), (before, paths))
        latest, _ = self.counts(self.git('rev-parse', 'HEAD').strip())
        self.assertEqual(latest['python_modules_compiled'], 2)

    def test_missing_short_or_caller_selected_commit_never_falls_back_to_head(self):
        for commit in ('HEAD', self.commit[:8], '0' * 40, '', '../HEAD'):
            with self.subTest(commit=commit), self.assertRaises(RuntimeError):
                CHECK.historical_source_counts(commit, ('test_boundary.py',))

    def test_local_git_replacement_cannot_substitute_the_recorded_source_tree(self):
        before, paths = self.counts()
        self.put('src/substituted.py', 'SUBSTITUTED = True\n')
        self.git('add', '--all')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Synthetic replacement tree')
        self.git('replace', self.commit, self.git('rev-parse', 'HEAD').strip())
        self.assertEqual(self.counts(), (before, paths))

    def test_historical_missing_required_member_and_release_inventory_refuse(self):
        with self.assertRaises(RuntimeError):
            CHECK.historical_source_counts(self.commit, ('test_missing.py',))
        self.put('RELEASE_MANIFEST.json', json.dumps({'release_files': ['missing.py']}))
        self.git('add', '--all')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Invalid synthetic release inventory')
        with self.assertRaises(RuntimeError):
            self.counts(self.git('rev-parse', 'HEAD').strip())

    def test_historical_counts_cannot_be_renewed_or_changed_to_current_counts(self):
        counts, _ = self.counts()
        CHECK.require_historical_counts(dict(counts), counts)
        for field in counts:
            for replacement in (counts[field] + 1, True, None):
                changed = dict(counts)
                changed[field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(RuntimeError):
                    CHECK.require_historical_counts(changed, counts)

    def test_object_reads_enforce_byte_bounds_and_hash_identity(self):
        with self.assertRaises(RuntimeError):
            CHECK.bounded_git_output(['show', self.commit + ':src/package.py'], 0)
        original = CHECK.bounded_git_output

        def substitute(arguments, maximum):
            value = original(arguments, maximum)
            return b'x' * len(value) if arguments[:2] == ['cat-file', 'blob'] else value

        with mock.patch.object(CHECK, 'bounded_git_output', side_effect=substitute):
            with self.assertRaises(RuntimeError):
                self.counts()

    def test_historical_evidence_hash_guard_rejects_rewriting_old_record(self):
        self.put('record.json', '{"historical":true}\n')
        identity = hashlib.sha256((self.root / 'record.json').read_bytes()).hexdigest()
        with mock.patch.object(CHECK, 'HISTORICAL_DETACHED_G2_SHA256', {'record.json': identity}), \
                mock.patch.object(CHECK, 'is_repository_checkout', return_value=True):
            CHECK.validate_historical_detached_evidence()
            self.put('record.json', '{"historical":false}\n')
            with self.assertRaises(RuntimeError):
                CHECK.validate_historical_detached_evidence()


if __name__ == '__main__':
    unittest.main()
