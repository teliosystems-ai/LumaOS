"""Host RAM admission oracles, not evidence of a completed VM installation."""
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import vm_memory
from vm_test import VM


def observation(available, total=8 * 1024 ** 2):
    return f'MemTotal:       {total} kB\nMemAvailable:   {available} kB\n'


class HostMemoryTests(unittest.TestCase):
    def test_exact_boundary_for_each_closed_guest_profile(self):
        for guest in (4096, 6144):
            needed_kib = (guest + 2048) * 1024
            with self.subTest(guest=guest):
                record = vm_memory.check_memory(guest, observation(needed_kib))
                self.assertEqual(record['host_available_bytes'], needed_kib * 1024)
                self.assertEqual(record['guest_memory_mib'], guest)
                self.assertEqual(record['host_reserve_bytes'], 2 * 1024 ** 3)
                self.assertIs(record['reservation'], False)
                with self.assertRaisesRegex(RuntimeError, 'RAM admission refused'):
                    vm_memory.check_memory(guest, observation(needed_kib - 1))

    def test_swap_free_or_total_cannot_substitute_for_available_ram(self):
        text = observation(20 * 1024) + 'MemFree: 999999999 kB\nSwapFree: 999999999 kB\n'
        with self.assertRaisesRegex(RuntimeError, 'swap is not capacity'):
            vm_memory.check_memory(6144, text)
        with self.assertRaises(ValueError):
            vm_memory.check_memory(6144, 'MemTotal: 999999999 kB\nMemFree: 999999999 kB\n')

    def test_invalid_duplicate_missing_or_inconsistent_observations_fail_closed(self):
        for text in ('', observation(1, 0), observation(-1), observation(9, 8),
                     observation(1) + 'MemAvailable: 1 kB\n',
                     observation(1) + 'MemTotal: 1 kB\n',
                     'MemTotal: 8000000 kB\nMemAvailable: 7000000 MB\n',
                     'MemTotal: 8000000 kB\nMemAvailable: 1.5 kB\n', 'x' * 65537):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                vm_memory.available_memory(text)

    def test_guest_size_is_closed_and_not_boolean_or_string(self):
        for guest in (True, 4096.0, '6144', 2048, 8192, None):
            with self.subTest(guest=guest), self.assertRaises(ValueError):
                vm_memory.check_memory(guest, observation(8 * 1024 ** 2))

    def test_live_observation_uses_fixed_path_and_bounded_read(self):
        with patch.object(Path, 'open', return_value=io.StringIO(observation(8 * 1024 ** 2))) as opened:
            self.assertEqual(vm_memory.admit_guest(6144)['guest_memory_mib'], 6144)
        opened.assert_called_once_with(encoding='ascii')
        with patch.object(Path, 'open', return_value=io.StringIO('x' * 65537)):
            with self.assertRaises(ValueError):
                vm_memory.admit_guest(6144)

    def test_refusal_precedes_stage_files_tpm_and_qemu(self):
        with patch('vm_test.admit_guest', side_effect=RuntimeError('insufficient RAM')) as admit, \
                patch('vm_test.Path.mkdir') as mkdir, \
                patch('vm_test.SoftwareTPM') as tpm, \
                patch('vm_test.subprocess.Popen') as launch, \
                self.assertRaisesRegex(RuntimeError, 'insufficient RAM'):
            VM(Path('/unused.img'), Path('/unused-stage'), Path('/unused.qcow2'),
               True, 60, memory_mib=6144)
        admit.assert_called_once_with(6144)
        mkdir.assert_not_called()
        tpm.assert_not_called()
        launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
