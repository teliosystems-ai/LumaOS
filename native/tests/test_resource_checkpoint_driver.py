import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('resource_checkpoint_integration.py')
SPEC = importlib.util.spec_from_file_location('resource_checkpoint_driver', SOURCE)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class ResourceCheckpointDriverTests(unittest.TestCase):
    def test_actual_private_ext4_fixture_root_and_closed_refusals(self):
        # The isolated suite supplies a real, owned ext4 work mount; never
        # replace a missing fixture prerequisite with a skipped success.
        supplied = os.environ['LUMA_STORAGE_TEST_ROOT']
        with tempfile.TemporaryDirectory(prefix='luma-tpm-driver-', dir=supplied) as folder:
            root = Path(folder)
            with patch.dict(os.environ, {'LUMA_STORAGE_TEST_ROOT': str(root)}):
                with DRIVER.fixture_parent() as selected:
                    self.assertEqual(selected, root)
                    self.assertEqual(selected.stat().st_mode & 0o7777, 0o700)
                root.chmod(0o755)
                with self.assertRaisesRegex(RuntimeError, 'mode0700'):
                    with DRIVER.fixture_parent():
                        self.fail('public fixture root accepted')
                root.chmod(0o700)
            alias = root / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            with patch.dict(os.environ, {'LUMA_STORAGE_TEST_ROOT': str(alias)}):
                with self.assertRaisesRegex(RuntimeError, 'symlink'):
                    with DRIVER.fixture_parent():
                        self.fail('fixture symlink accepted')
            alias.unlink()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'explicit private'):
                with DRIVER.fixture_parent():
                    self.fail('implicit default fixture accepted')
        with patch.dict(os.environ, {'LUMA_STORAGE_TEST_ROOT': '/tmp'}):
            with self.assertRaisesRegex(RuntimeError, 'writable ancestor'):
                with DRIVER.fixture_parent():
                    self.fail('world-writable fixture ancestor accepted')
        # /dev is real tmpfs in the fresh, no-device-access tools container.
        with tempfile.TemporaryDirectory(prefix='luma-tpm-not-ext4-', dir='/dev') as folder:
            with patch.dict(os.environ, {'LUMA_STORAGE_TEST_ROOT': folder}):
                with self.assertRaisesRegex(RuntimeError, 'actual writable ext4'):
                    with DRIVER.fixture_parent():
                        self.fail('tmpfs fixture accepted')

    def test_requires_exactly_one_named_executed_test(self):
        name = DRIVER.CASES[0]
        valid = (f'running 1 test\ntest {name} ... ok\n'
                 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                 '858 filtered out; finished in 0.17s\n')
        DRIVER.require_single_execution(name, valid)
        invalid = (
            valid.replace('running 1 test', 'running 0 tests').replace('1 passed', '0 passed'),
            valid.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored'),
            valid.replace(name, 'another::test'),
            valid + valid,
            valid.replace(f'test {name} ... ok\n', ''),
            valid.replace('test result: ok.', 'test result: FAILED.'),
        )
        for output in invalid:
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    DRIVER.require_single_execution(name, output)


if __name__ == '__main__':
    unittest.main()
