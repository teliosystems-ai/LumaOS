"""Desktop acceptance oracles; synthetic responses are not image acceptance."""
import contextlib
import io
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import desktop_vm_test as desktop
import vm_display


class GreeterTests(unittest.TestCase):
    def test_live_snapshot_memory_is_separate_from_installed_desktop(self):
        self.assertEqual(desktop.stage_memory('install'), 6144)
        for stage in ('installed-greeter', 'cold-greeter'):
            self.assertEqual(desktop.stage_memory(stage), 4096)
        with self.assertRaises(KeyError):
            desktop.stage_memory('unqualified')

    def test_failure_diagnostics_include_live_storage_and_memory(self):
        vm = Mock()
        self.assertTrue(desktop.diagnostics(vm))
        command = vm.run.call_args.args[0]
        self.assertIn('df -B1 /var', command)
        self.assertIn('free -b', command)
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 30)

    def test_only_low_memory_fixture_expects_model_ram_refusal(self):
        for memory in (4096, 6144):
            vm = Mock(memory_mib=memory, acceleration='tcg')
            vm.run.side_effect = lambda command, **kwargs: (
                b'release signature verification failed' if '/tmp/bad-bundle --model' in command
                else b'cannot be admitted' if '--model qwen3-4b' in command else b'')
            with contextlib.redirect_stdout(io.StringIO()):
                desktop.install(vm)
            commands = [call.args[0] for call in vm.run.call_args_list]
            self.assertEqual(any('--model qwen3-4b' in command for command in commands), memory == 4096)
            self.assertTrue(any('/tmp/bad-bundle --model' in command for command in commands))

    def test_image_edition_name_and_digest_are_bound_before_guest_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            image = root / 'fixture.img'
            image.write_bytes(b'public synthetic fixture, not a bootable image')
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            record = {'edition': 'desktop', 'image': image.name, 'image_sha256': digest}
            (root / 'build.json').write_text(json.dumps(record))
            self.assertEqual(desktop.verified_image(image), digest)
            for field, value in (('edition', 'headless'), ('image', 'other.img'), ('image_sha256', '0'*64)):
                changed = {**record, field: value}
                (root / 'build.json').write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    desktop.verified_image(image)

    def record(self):
        return {'desktop_greeter': {'Name': 'gdm', 'Class': 'greeter', 'Type': 'wayland',
                                   'Remote': 'no', 'Active': 'yes', 'Seat': 'seat0',
                                   'Service': 'gdm-launch-environment'},
                'user_login_tested': False, 'gate_closing': False}

    def test_exact_fresh_local_wayland_greeter_only(self):
        record = self.record()
        self.assertEqual(desktop.greeter_result(json.dumps(record).encode()), record)
        for field, value in (('Name', 'lumauser'), ('Type', 'x11'), ('Class', 'user'),
                             ('Remote', 'yes'), ('Active', 'no'), ('Seat', ''),
                             ('Service', 'login')):
            changed = self.record()
            changed['desktop_greeter'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                desktop.greeter_result(json.dumps(changed).encode())

    def test_missing_duplicate_and_overclaimed_result_refused(self):
        record = self.record()
        encoded = json.dumps(record).encode()
        for output in (b'', encoded + b'\n' + encoded, b'prompt ' + encoded):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                desktop.greeter_result(output)
        for field in ('user_login_tested', 'gate_closing'):
            record = self.record()
            record[field] = True
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                desktop.greeter_result(json.dumps(record).encode())

    def test_probe_is_read_only_and_bounded(self):
        vm = Mock()
        vm.run.return_value = json.dumps(self.record()).encode()
        self.assertEqual(desktop.observe_greeter(vm), self.record())
        command = vm.run.call_args.args[0]
        self.assertIn("'show-session'", command.replace("'\"'\"'", "'"))
        self.assertNotIn('AutomaticLogin', command)
        self.assertNotIn('start-session', command)
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 650)

    def test_options_are_explicit_and_timeout_is_bounded(self):
        args = ['--image', '/absent', '--work', '/absent']
        defaults = desktop.arguments(args)
        self.assertFalse(defaults.secure_boot)
        self.assertFalse(defaults.require_clean_shutdown)
        strict = desktop.arguments(args + ['--secure-boot', '--require-clean-shutdown', '--accel', 'tcg'])
        self.assertTrue(strict.secure_boot)
        self.assertTrue(strict.require_clean_shutdown)
        for value in ('59', '21601', 'forever'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                desktop.arguments(args + ['--timeout', value])


class DisplayTests(unittest.TestCase):
    def test_virtual_gpu_is_explicit_and_has_no_host_rendering(self):
        self.assertEqual(vm_display.display_arguments(False), [])
        self.assertEqual(vm_display.display_arguments(True), ['-vga', 'none', '-device', 'virtio-vga'])
        for value in (1, 'true', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                vm_display.display_arguments(value)

    def exercise(self, root, responses=None, png=None, name='greeter', deadline=None):
        vm = SimpleNamespace(work=root / 'stage', socket_dir=root / 'sockets',
                             deadline=deadline if deadline is not None else time.monotonic() + 40)
        vm.work.mkdir(exist_ok=True)
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        if responses is None:
            responses = [{'QMP': {'version': {}}}, {'return': {}, 'id': 'capabilities'},
                         {'event': 'DISPLAY_CHANGED'}, {'return': {}, 'id': 'screenshot'}]
        connection.recv.side_effect = [
            item if isinstance(item, bytes) else json.dumps(item).encode() + b'\r\n'
            for item in responses]

        def send(data):
            request = json.loads(data)
            if request['execute'] == 'screendump':
                target = Path(request['arguments']['filename'])
                target.write_bytes(png if png is not None else
                                   b'\x89PNG\r\n\x1a\n' + struct.pack('!I', 13) + b'IHDR' +
                                   struct.pack('!II', 1024, 768))
        connection.sendall.side_effect = send
        # The transport is entirely mocked; Windows need not expose AF_UNIX.
        with patch.object(vm_display.socket, 'AF_UNIX', 1, create=True), \
                patch.object(vm_display.socket, 'socket', return_value=connection):
            result = vm_display.screenshot(vm, name)
        return result, connection

    def test_greeting_capabilities_events_and_exact_reply_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            result, connection = self.exercise(Path(folder))
            self.assertEqual(result, {'path': 'stage/screen-greeter.png', 'width': 1024, 'height': 768})
            sent = [json.loads(call.args[0]) for call in connection.sendall.call_args_list]
            self.assertEqual([request['execute'] for request in sent], ['qmp_capabilities', 'screendump'])
            self.assertEqual(sent[-1]['arguments']['format'], 'png')

    def test_closed_bad_id_error_oversized_or_missing_greeting_refused(self):
        for index, replies in enumerate((
            [b''],
            [{'return': {}}],
            [{'QMP': {}}, {'return': {}, 'id': 'wrong'}],
            [{'QMP': {}}, {'error': {'class': 'GenericError'}, 'id': 'capabilities'}],
            [b'x' * 65537],
        )):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as folder, \
                    self.assertRaises(RuntimeError):
                self.exercise(Path(folder), replies)

    def test_existing_file_bad_name_and_expired_deadline_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'stage').mkdir()
            target = root / 'stage/screen-greeter.png'
            target.write_bytes(b'preserve')
            with self.assertRaises(ValueError):
                self.exercise(root)
            self.assertEqual(target.read_bytes(), b'preserve')
            with self.assertRaises(ValueError):
                self.exercise(root, name='../outside')
            with self.assertRaises(TimeoutError):
                self.exercise(root, name='failure', deadline=0)

    def test_non_png_and_unexpected_dimensions_refused(self):
        for png in (b'x' * 24, b'\x89PNG\r\n\x1a\n' + struct.pack('!I', 13) + b'IHDR' +
                    struct.pack('!II', 1, 1)):
            with self.subTest(png=png), tempfile.TemporaryDirectory() as folder, \
                    self.assertRaises(RuntimeError):
                self.exercise(Path(folder), png=png)


if __name__ == '__main__':
    unittest.main()
