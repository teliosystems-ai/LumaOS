"""Console drainage checks, not evidence of a booted operating system."""
import io
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
from vm_test import VM


class ConsoleDrainTests(unittest.TestCase):
    def guest(self, chunks, code=0):
        vm = VM.__new__(VM)
        vm.deadline = time.monotonic()+5
        vm.process = Mock()
        vm.process.poll.return_value = code
        vm.process.returncode = code
        vm.console = Mock()
        vm.console.recv.side_effect = chunks
        vm.log = io.BytesIO()
        vm.buffer = b''
        return vm

    def test_exit_drains_multiple_queued_chunks_including_shutdown_marker(self):
        chunks = [b'a'*65536, b'b'*65536, b'\nLUMA_SHUTDOWN_STORAGE_CLEAN\n', b'']
        vm = self.guest(chunks)
        with patch('vm_test.select.select', return_value=([vm.console], [], [])):
            self.assertEqual(vm.wait_exit(), 0)
        self.assertEqual(vm.log.getvalue(), b''.join(chunks))
        self.assertEqual(vm.buffer, b''.join(chunks))

    def test_exit_without_queued_output_does_not_block_for_eof(self):
        vm = self.guest([])
        with patch('vm_test.select.select', return_value=([], [], [])):
            self.assertEqual(vm.wait_exit(), 0)
        vm.console.recv.assert_not_called()

    def test_eof_preserves_nonzero_exit(self):
        vm = self.guest([b''], 7)
        with patch('vm_test.select.select', return_value=([vm.console], [], [])):
            self.assertEqual(vm.wait_exit(), 7)


if __name__ == '__main__':
    unittest.main()
