"""Recovery-fixture oracles; these do not execute an installed image."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
from vm_test import atomic_export_checks


class Guest:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.commands = []

    def run(self, command):
        self.commands.append(command)

    def send(self, command):
        self.commands.append(command)

    def expect(self, pattern):
        if b'__EXPORT_FAIL_RC=' in pattern:
            return next(self.responses)
        return b'public fixture prompt'


class RecoveryFixtureTests(unittest.TestCase):
    def test_both_required_refusals_and_retained_partial_are_checked(self):
        guest = Guest([
            b'export incomplete; retain luma-user-data.tar.partial\r\n__EXPORT_FAIL_RC=1__\r\n',
            b'export requires an empty directory\r\n__EXPORT_FAIL_RC=1__\r\n',
        ])
        atomic_export_checks(guest)
        self.assertIn('sha256sum -c /tmp/export-partial.sha256', guest.commands)
        self.assertEqual(guest.commands[-1], 'umount /tmp/luma-export-full')
        self.assertTrue(any('tar -xOf' in command for command in guest.commands))

    def test_wrong_failure_boundary_or_success_status_is_not_accepted(self):
        for response in (
            b'wrong credential\r\n__EXPORT_FAIL_RC=1__\r\n',
            b'export incomplete; retain luma-user-data.tar.partial\r\n__EXPORT_FAIL_RC=0__\r\n',
        ):
            guest = Guest([response])
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                atomic_export_checks(guest)
            self.assertEqual(guest.commands[-1], 'umount /tmp/luma-export-full')

    def test_second_attempt_must_refuse_existing_partial_not_repeat_writer(self):
        response = b'export incomplete; retain luma-user-data.tar.partial\r\n__EXPORT_FAIL_RC=1__\r\n'
        guest = Guest([response, response])
        with self.assertRaises(RuntimeError):
            atomic_export_checks(guest)
        self.assertEqual(guest.commands[-1], 'umount /tmp/luma-export-full')


if __name__ == '__main__':
    unittest.main()
