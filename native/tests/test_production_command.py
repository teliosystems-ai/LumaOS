"""Actual verifier-process bounds in disposable software tests only."""
import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'image'))
import production_release as production


@unittest.skipUnless(os.name == 'posix', 'Linux selector pipe supervision')
class ProductionCommandTests(unittest.TestCase):
    def test_actual_stdin_and_stderr_do_not_change_returned_stdout(self):
        code = ('import sys; data=sys.stdin.buffer.read(); '
                'sys.stderr.buffer.write(b"diagnostic"); sys.stdout.buffer.write(data)')
        self.assertEqual(production.command(sys.executable, '-c', code, input_bytes=b'public bytes'),
                         b'public bytes')

    def test_oversized_or_nonbytes_stdin_refuses_before_spawn(self):
        with patch.object(production.subprocess, 'Popen') as spawn:
            for data in (bytes(65537), 'not byte input'):
                with self.assertRaises(ValueError):
                    production.command(sys.executable, input_bytes=data)
            spawn.assert_not_called()

    def test_actual_stdout_and_stderr_share_one_streaming_bound(self):
        code = ('import sys; sys.stdout.buffer.write(b"x" * (3 * 1024 * 1024)); '
                'sys.stdout.buffer.flush(); sys.stderr.buffer.write(b"y" * (3 * 1024 * 1024)); '
                'sys.stderr.buffer.flush()')
        with self.assertRaisesRegex(ValueError, 'streaming bound'):
            production.command(sys.executable, '-c', code)

    def test_deadline_kills_and_reaps_the_actual_owned_process(self):
        original = production.subprocess.Popen
        processes = []
        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(production.subprocess, 'Popen', side_effect=spawn), \
                patch.object(production, 'time') as clock:
            clock.monotonic.side_effect = [0, 121]
            with self.assertRaisesRegex(ValueError, 'deadline'):
                production.command(sys.executable, '-c', 'import time; time.sleep(60)')
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertNotEqual(processes[0].returncode, 0)

    def test_declared_extra_phase_members_cannot_export_private_or_unknown_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            production.request_group(out, 'release',
                {'release.json': b'public fixture', 'private.key': b'forbidden fixture'},
                {'signer': 'fixture', 'public_inputs': {}, 'signature_algorithm': 'Ed25519-raw-message'})
            with self.assertRaisesRegex(ValueError, 'unknown/private'):
                production.read_request(out, 'release')

    def test_request_schema_bool_and_alternate_algorithm_are_refused(self):
        for schema, algorithm in ((True, 'Ed25519-raw-message'), (1, 'caller-algorithm')):
            with tempfile.TemporaryDirectory() as temporary:
                out = Path(temporary)
                production.request_group(out, 'release', {'release.json': b'public fixture'},
                    {'signer': 'fixture', 'public_inputs': {}, 'signature_algorithm': algorithm})
                path = out / 'production-release-request/request.json'
                request = json.loads(path.read_bytes())
                request['schema_version'] = schema
                path.write_bytes(production.canonical(request))
                with self.assertRaises(ValueError):
                    production.read_request(out, 'release')


if __name__ == '__main__':
    unittest.main()
