import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name('resource_checkpoint_integration.py')
SPEC = importlib.util.spec_from_file_location('resource_checkpoint_driver', SOURCE)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class ResourceCheckpointDriverTests(unittest.TestCase):
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
