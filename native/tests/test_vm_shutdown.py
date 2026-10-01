"""Fixture-only assertions; these are not evidence of an OS power-off."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('vm_shutdown',
    Path(__file__).resolve().parents[1]/'image/vm_shutdown.py')
shutdown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shutdown)


class GuestFixture:
    def __init__(self, work, output=b'', code=0):
        self.work, self.output, self.code = work, output, code
        self.commands = []
        (work/'serial.log').write_bytes(b'old console output\n')

    def run(self, command):
        self.commands.append(command)

    def send(self, command):
        self.commands.append(command)

    def wait_exit(self):
        with (self.work/'serial.log').open('ab') as stream:
            stream.write(self.output)
        return self.code


class ShutdownFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_strict_shutdown_requires_preparation_and_new_positive_marker(self):
        guest = GuestFixture(self.root, b'\r\nLUMA_SHUTDOWN_STORAGE_CLEAN\r\n')
        shutdown.poweroff(guest, True)
        self.assertIn('dracut-shutdown.service', guest.commands[0])
        self.assertEqual(guest.commands[-2:], ['sync', 'systemctl poweroff'])

    def test_missing_partial_echoed_or_old_marker_is_not_a_pass(self):
        for output in (b'', b'LUMA_SHUTDOWN_STORAGE_CLEAN',
                       b'echo LUMA_SHUTDOWN_STORAGE_CLEAN\r\n',
                       b'LUMA_SHUTDOWN_STORAGE_CLEAN extra\n'):
            with self.subTest(output=output):
                guest = GuestFixture(self.root, output)
                (self.root/'serial.log').write_bytes(b'LUMA_SHUTDOWN_STORAGE_CLEAN\n')
                with self.assertRaises(RuntimeError):
                    shutdown.poweroff(guest, True)

    def test_nonzero_exit_is_never_accepted(self):
        for strict in (False, True):
            guest = GuestFixture(self.root, b'LUMA_SHUTDOWN_STORAGE_CLEAN\n', 1)
            with self.assertRaises(RuntimeError):
                shutdown.poweroff(guest, strict)

    def test_legacy_mode_still_requests_real_poweroff(self):
        guest = GuestFixture(self.root)
        shutdown.poweroff(guest)
        self.assertEqual(guest.commands, ['sync', 'systemctl poweroff'])

    def test_stage_completion_checks_secure_boot_before_clean_poweroff(self):
        guest = GuestFixture(self.root, b'\r\nLUMA_SHUTDOWN_STORAGE_CLEAN\r\n')
        shutdown.finish_stage(guest, secure_boot=True, require_clean=True)
        self.assertIn('SecureBoot-8be4df61', guest.commands[0])
        self.assertIn('dracut-shutdown.service', guest.commands[1])
        self.assertEqual(guest.commands[-2:], ['sync', 'systemctl poweroff'])

    def test_failed_secure_boot_check_cannot_be_stage_completion(self):
        guest = mock.Mock()
        guest.run.side_effect = RuntimeError('Secure Boot disabled')
        with mock.patch.object(shutdown, 'poweroff') as poweroff, self.assertRaises(RuntimeError):
            shutdown.finish_stage(guest, secure_boot=True, require_clean=True)
        poweroff.assert_not_called()

    def test_failed_shutdown_propagates_out_of_stage_completion(self):
        guest = GuestFixture(self.root, code=1)
        with self.assertRaises(RuntimeError):
            shutdown.finish_stage(guest)


if __name__ == '__main__':
    unittest.main()
