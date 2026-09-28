"""Software TPM fixture lifecycle, ownership and QEMU transport tests."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parents[1]/'image'
spec = importlib.util.spec_from_file_location('vm_tpm', IMAGE/'vm_tpm.py')
vm_tpm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm_tpm)


class TpmLocationTests(unittest.TestCase):
    def test_external_state_namespace_is_stable_and_run_specific(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.dict(os.environ, {'LUMA_VM_TPM_ROOT':str(root)}):
                a = vm_tpm.state_directory(root/'vm-a')
                self.assertEqual(a, vm_tpm.state_directory(root/'vm-a'))
                self.assertNotEqual(a, vm_tpm.state_directory(root/'vm-b'))
                self.assertEqual(a.parent, root)
            with patch.dict(os.environ, {'LUMA_VM_TPM_ROOT':'relative'}):
                with self.assertRaises(RuntimeError):vm_tpm.state_directory(root)


@unittest.skipUnless(os.name == 'posix' and Path('/.dockerenv').is_file()
                     and shutil.which('swtpm') and shutil.which('qemu-system-x86_64'),
                     'requires isolated Linux tools container')
class TpmLifecycleTests(unittest.TestCase):
    def test_lock_restart_and_qemu_transport(self):
        with tempfile.TemporaryDirectory(prefix='luma-tpm-vm-test-') as folder:
            work = Path(folder)
            directory = work/'private-tpm'
            fixture = vm_tpm.SoftwareTPM(directory)
            try:
                with self.assertRaises(BlockingIOError):vm_tpm.SoftwareTPM(directory)
                control = fixture.control
                process = subprocess.Popen(['qemu-system-x86_64', '-machine', 'q35,accel=tcg',
                    '-m', '128', '-nodefaults', '-display', 'none', '-S', '-monitor', 'none',
                    '-qmp', 'stdio', *fixture.qemu_arguments()],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    # communicate has a bounded timeout and avoids a blocking
                    # readline when QEMU startup fails before the greeting.
                    commands = b'{"execute":"qmp_capabilities"}\n{"execute":"query-tpm"}\n{"execute":"quit"}\n'
                    output, error = process.communicate(commands, timeout=15)
                    self.assertEqual(process.returncode, 0, error.decode(errors='replace'))
                    messages = [json.loads(line) for line in output.splitlines()]
                    devices = [item['return'] for item in messages if isinstance(item.get('return'), list)]
                    self.assertEqual(len(devices), 1, output)
                    self.assertEqual(devices[0][0]['model'], 'tpm-tis')
                    self.assertEqual(devices[0][0]['options']['type'], 'emulator')
                finally:
                    if process.poll() is None:process.kill()
                    process.wait()
                    for stream in (process.stdin, process.stdout, process.stderr):stream.close()
            finally:
                fixture.close()
                fixture.close()  # idempotent teardown
            self.assertFalse(control.exists())
            # QEMU initialization must have created state; restarting the
            # fixture must retain it. This is not NV enrollment qualification.
            files = {p.name:p.read_bytes() for p in (directory/'state').iterdir() if p.is_file()}
            self.assertTrue(files)
            restarted = vm_tpm.SoftwareTPM(directory)
            restarted.close()
            self.assertEqual(files, {p.name:p.read_bytes() for p in (directory/'state').iterdir() if p.is_file()})

    def test_public_or_symlink_state_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='luma-tpm-vm-test-') as folder:
            work = Path(folder)
            directory = work/'public'
            directory.mkdir(mode=0o755)
            with self.assertRaises(RuntimeError):vm_tpm.SoftwareTPM(directory)
            alias = work/'alias'
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(RuntimeError):vm_tpm.SoftwareTPM(alias)

    def test_failed_start_releases_lock_and_sockets(self):
        with tempfile.TemporaryDirectory(prefix='luma-tpm-vm-test-') as folder:
            directory = Path(folder)/'private-tpm'
            with patch.object(vm_tpm.subprocess, 'Popen', side_effect=FileNotFoundError('fixture failure')):
                with self.assertRaises(FileNotFoundError):vm_tpm.SoftwareTPM(directory)
            fixture = vm_tpm.SoftwareTPM(directory)
            fixture.close()

    def test_linked_state_is_not_opened_or_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='luma-tpm-vm-test-') as folder:
            work = Path(folder)
            directory = work/'private-tpm'
            directory.mkdir(mode=0o700)
            state = directory/'state'
            state.mkdir(mode=0o700)
            outside = work/'outside'
            outside.write_bytes(b'preserve')
            outside.chmod(0o600)
            member = state/'tpm2-00.permall'
            member.symlink_to(outside)
            with self.assertRaises(RuntimeError):vm_tpm.SoftwareTPM(directory)
            member.unlink()
            os.link(outside, member)
            with self.assertRaises(RuntimeError):vm_tpm.SoftwareTPM(directory)
            self.assertEqual(outside.read_bytes(), b'preserve')


if __name__ == '__main__':unittest.main()
