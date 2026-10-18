"""Actual bounded transport/frame tests; no real UTC, TPM or commissioning."""
import importlib.util
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('luma_windows_utc_front_tests', Path(__file__).resolve().parents[1] / 'utc/windows_front.py')
front = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(front)


def challenge():
    return struct.pack('>I', len(front.CHALLENGE)) + front.CHALLENGE + bytes([1])*32 + bytes([2])*32 + bytes([3])*32


def delivery():
    proof = struct.pack('>I', len(front.PROOF)) + front.PROOF + challenge()[-96:] + struct.pack('>QQ', 1800000000000, 1800000000500)
    # These bytes intentionally are NOT a real signature. The frontend may only
    # check framing/binding; actual Windows must independently verify BCrypt.
    return struct.pack('>I', len(front.DELIVERY)) + front.DELIVERY + struct.pack('>I', len(proof)) + proof + bytes([4])*64


class WindowsUtcFrontTests(unittest.TestCase):
    def exchange(self, payload):
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        return front.request(server, 'time.example.test', time.monotonic()+1)

    def request(self, body=None, headers=b''):
        body = challenge() if body is None else body
        return (b'POST /luma/utc/v1 HTTP/1.1\r\nHost: time.example.test:8443\r\n'
                b'Content-Type: application/octet-stream\r\nContent-Length: ' + str(len(body)).encode()
                + b'\r\n' + headers + b'\r\n' + body)

    def test_actual_socket_framing_preserves_exact_nonce_installation_and_release(self):
        self.assertEqual(self.exchange(self.request()), challenge())
        self.assertEqual(front.delivery(delivery(), challenge()), delivery())

    def test_closed_header_route_host_size_and_slow_truncated_stream_refusals(self):
        initial = self.request()
        variants = [initial.replace(b'POST ', b'GET ', 1), initial.replace(b'/luma/utc/v1', b'/arbitrary'),
                    initial.replace(b'HTTP/1.1', b'HTTP/1.0'), initial.replace(b'time.example.test:', b'other.example.test:'),
                    initial.replace(b'application/octet-stream', b'application/json'),
                    self.request(headers=b'Content-Length: 1\r\n'), self.request(headers=b'Transfer-Encoding: chunked\r\n'),
                    self.request(headers=b'Expect: 100-continue\r\n'), self.request(headers=b'Bad : value\r\n'),
                    self.request(headers=b' Folded: value\r\n'), self.request(headers=b'X-Large: '+b'x'*4096+b'\r\n'),
                    self.request(body=b'x'*1025), initial[:-1], initial.replace(b'Content-Length: ', b'Content-Length: 0')]
        for variant in variants:
            with self.subTest(length=len(variant)), self.assertRaises((ValueError, TimeoutError)):
                self.exchange(variant)
        a, b = socket.socketpair()
        with a, b:
            with self.assertRaises(TimeoutError):
                front.receive(a, 1, time.monotonic()+0.01)

    def test_cross_purpose_zero_fields_interval_and_delivery_substitution_refuse(self):
        for item in [b'', challenge()+b'x', challenge()[:-1], bytes(len(challenge()))]:
            with self.assertRaises(ValueError):
                front.challenge(item)
        initial = delivery()
        for index in [0, 4, len(initial)-64-8, len(initial)-64-16-96]:
            changed = bytearray(initial)
            changed[index] ^= 1
            with self.assertRaises(ValueError):
                front.delivery(bytes(changed), challenge())
        with self.assertRaises(ValueError):
            front.delivery(initial+b'x', challenge())

    def test_actual_chunked_sender_and_receiver_have_original_absolute_deadline(self):
        a, b = socket.socketpair()
        payload = b'exact transport bytes'*100
        errors = []
        def writer():
            try:
                front.send(b, payload, time.monotonic()+1)
            except Exception as error:
                errors.append(error)
        with a, b:
            thread = threading.Thread(target=writer)
            thread.start()
            self.assertEqual(front.receive(a, len(payload), time.monotonic()+1), payload)
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            with self.assertRaises(TimeoutError):
                front.send(b, b'one', time.monotonic()-1)

    def test_canonical_configuration_and_inert_data_cannot_claim_runtime_admission(self):
        for value in [b'{"a":1,"a":1}', b'{"a":NaN}', b'{} ', b'\xff']:
            with self.assertRaises((ValueError, UnicodeError)):
                front.canonical(value)
        self.assertEqual(front.canonical(b'{"a":1}'), {'a':1})
        with self.assertRaises(ValueError):
            front.runtime(b'{"schema_version":1}')

    def test_actual_ephemeral_tls_handshake_and_exact_https_body_delivery(self):
        # A disposable test-only certificate is explicitly trusted by this
        # client context only. No host trust store, TPM or TimeKey is touched.
        with tempfile.TemporaryDirectory(prefix='luma-utc-tls-') as directory:
            key=Path(directory)/'key.pem'
            cert=Path(directory)/'certificate.pem'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                            '-nodes','-keyout',str(key),'-out',str(cert),'-days','1',
                            '-subj','/CN=time.example.test','-addext','subjectAltName=DNS:time.example.test'],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                           env={'PATH':'/usr/bin','OPENSSL_CONF':'/dev/null'},timeout=10)
            server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version=ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(cert,key)
            client_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.minimum_version=ssl.TLSVersion.TLSv1_2
            client_context.load_verify_locations(cafile=cert)
            a,b=socket.socketpair()
            errors=[]
            def server():
                try:
                    with server_context.wrap_socket(a,server_side=True) as stream:
                        self.assertEqual(front.request(stream,'time.example.test',time.monotonic()+2),challenge())
                        front.send(stream,delivery(),time.monotonic()+2)
                except Exception as error:
                    errors.append(error)
            thread=threading.Thread(target=server)
            thread.start()
            try:
                with client_context.wrap_socket(b,server_hostname='time.example.test') as stream:
                    self.assertIn(stream.version(),('TLSv1.2','TLSv1.3'))
                    front.send(stream,self.request(),time.monotonic()+2)
                    received=front.receive(stream,len(delivery()),time.monotonic()+2)
                    self.assertEqual(front.delivery(received,challenge()),delivery())
            finally:
                a.close();b.close();thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])


if __name__ == '__main__':
    unittest.main()
