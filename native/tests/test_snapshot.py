"""Native source capture tests; no Docker, network, signing or disk images."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import snapshot


@unittest.skipUnless(os.name == 'posix', 'Linux source capture semantics')
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root/'repo'
        for name in snapshot.FOLDERS:
            path = self.repository/name
            path.mkdir(parents=True)
            (path/'fixture.txt').write_text(name+' fixture\n')
        (self.repository/'LICENSE').write_text('license fixture\n')
        self.output = self.root/'captured'

    def test_captured_bytes_hashes_modes_and_excluded_caches(self):
        script = self.repository/'native/image/build.sh'
        script.write_text('#!/bin/sh\nexit 0\n')
        script.chmod(0o755)
        cache = self.repository/'rust/target'
        cache.mkdir()
        (cache/'binary').write_bytes(b'not build input')
        record = snapshot.capture(self.repository, self.output)
        self.assertFalse((self.output/'rust/target').exists())
        self.assertEqual((self.output/'native/image/build.sh').stat().st_mode & 0o777, 0o555)
        for item in record['files']:
            data = (self.output/item['path']).read_bytes()
            self.assertEqual(len(data), item['bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item['sha256'])
        script.write_text('later checkout change')
        self.assertEqual((self.output/'native/image/build.sh').read_text(), '#!/bin/sh\nexit 0\n')

    def test_existing_destination_and_recursive_output_refused(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, self.output)
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, self.repository/'src/captured')

    def test_linked_file_linked_source_root_and_special_file_refused(self):
        linked = self.repository/'src/linked'
        linked.symlink_to('/absent')
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, self.output)
        linked.unlink()
        os.mkfifo(linked)
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, self.output)
        linked.unlink()
        source = self.repository/'native'
        source.rename(self.repository/'original-native')
        source.symlink_to('original-native')
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, self.output)

    def test_mutation_during_capture_cannot_publish_completion_manifest(self):
        real_inventory = snapshot.inventory
        def changed(repository, include_tests=False):
            if self.output.exists():
                (repository/'src/new-file').write_text('concurrent edit')
            return real_inventory(repository, include_tests=include_tests)
        with mock.patch.object(snapshot, 'inventory', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                snapshot.capture(self.repository, self.output)
        self.assertFalse((self.output/'build-inputs.json').exists())

    def test_test_lane_captures_and_bounds_native_fixtures(self):
        tests = self.repository/'native/tests'
        tests.mkdir()
        fixture = tests/'pam_account_driver.c'
        fixture.write_text('fixture source\n')
        self.assertNotIn('native/tests/pam_account_driver.c',
                         snapshot.inventory(self.repository))
        record = snapshot.capture(self.repository, self.output, include_tests=True)
        self.assertIn('native/tests/pam_account_driver.c',
                      {item['path'] for item in record['files']})
        self.assertEqual((self.output/'native/tests/pam_account_driver.c').read_text(),
                         'fixture source\n')
        with self.assertRaises(ValueError):
            snapshot.capture(self.repository, tests/'recursive', include_tests=True)

    def test_file_count_size_and_total_bounds(self):
        for bound, limit in (('MAX_FILE', 1), ('MAX_TOTAL', 1), ('MAX_FILES', 1)):
            with self.subTest(bound=bound), mock.patch.object(snapshot, bound, limit):
                with self.assertRaises(ValueError):
                    snapshot.capture(self.repository, self.output)
            self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
