"""Probe framing checks, not acceptance of the installed broker."""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
import broker_vm_probe as probe


@unittest.skipUnless(hasattr(socket, 'AF_UNIX') and hasattr(socket, 'socketpair'), 'Unix sockets required')
class BrokerProbeTests(unittest.TestCase):
    def response(self, data):
        a, b = socket.socketpair()
        with a, b:
            a.sendall(data)
            a.shutdown(socket.SHUT_WR)
            return probe.receive(b)

    def test_bounded_framed_json_round_trip(self):
        body = b'{"schema_version":1,"result":"denied"}'
        self.assertEqual(self.response(struct.pack('!I', len(body))+body),
                         {'schema_version': 1, 'result': 'denied'})

    def test_invalid_size_truncation_and_malformed_json_refused(self):
        for data in (b'', b'\0\0', struct.pack('!I', 0), struct.pack('!I', 16385),
                     struct.pack('!I', 3)+b'{}', struct.pack('!I', 1)+b'x'):
            with self.subTest(data=data), self.assertRaises((RuntimeError, ValueError)):
                self.response(data)

    def test_request_binds_current_identity_and_only_status(self):
        with patch.object(probe.os, 'geteuid', return_value=990):
            frame = probe.request('fixture')
        self.assertEqual(struct.unpack('!I', frame[:4])[0], len(frame)-4)
        body = json.loads(frame[4:])
        self.assertEqual(body['caller'], 990)
        self.assertEqual(body['action'], 'status')

    def test_root_is_not_accepted_as_control_identity(self):
        with patch.object(probe.os, 'geteuid', return_value=0), self.assertRaises(RuntimeError):
            probe.main()


if __name__ == '__main__':
    unittest.main()
