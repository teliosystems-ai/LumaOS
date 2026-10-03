"""Bounded, fixed-loopback model readiness checks without loading weights."""

import importlib.util
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
import unittest
import urllib.error
import urllib.request


SCRIPT = Path(__file__).resolve().parents[1] / 'image/overlay/usr/libexec/luma-os/model-health.py'
SPEC = importlib.util.spec_from_file_location('model_health', SCRIPT)
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.limit = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        self.limit = limit
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        assert request.full_url == health.URL
        assert request.get_method() == 'GET'
        assert 0 < timeout <= 3
        return self.response


class ModelHealthTests(unittest.TestCase):
    def test_only_bounded_unique_ok_reply_is_ready(self):
        self.assertTrue(health.parse_health(b'{"status":"ok"}'))
        for body in (b'', b'not json', b'[]', b'{"status":"loading model"}',
                     b'{"status":"ok","status":"loading model"}',
                     b'{"status":"ok","extra":NaN}', b'x' * 4097):
            self.assertFalse(health.parse_health(body))

    def test_probe_is_fixed_get_and_bounded(self):
        response = FakeResponse(200, b'{"status":"ok"}')
        self.assertTrue(health.probe(3, FakeOpener(response)))
        self.assertEqual(response.limit, 4097)
        self.assertFalse(health.probe(3, FakeOpener(FakeResponse(503, b'{"status":"ok"}'))))
        self.assertFalse(health.probe(3, FakeOpener(FakeResponse(200, b'x' * 4097))))
        with self.assertRaises(ValueError):
            health.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://elsewhere')

    def test_loopback_http_accepts_ok_and_refuses_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/health')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header('Content-Length', '15')
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok"}')

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        previous_url = health.URL
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 health.NoRedirect())
            health.URL = f'http://127.0.0.1:{server.server_port}/health'
            self.assertTrue(health.probe(1, opener))
            health.URL = f'http://127.0.0.1:{server.server_port}/redirect'
            with self.assertRaises(ValueError):
                health.probe(1, opener)
        finally:
            health.URL = previous_url
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

    def test_poll_retries_transient_errors_and_has_whole_deadline(self):
        clock = [0.0]
        attempts = []

        def probe(timeout):
            attempts.append(timeout)
            if len(attempts) == 1:
                raise urllib.error.URLError('not yet listening')
            return len(attempts) == 3

        health.wait_ready(probe, seconds=8,
                          now=lambda: clock[0], sleep=lambda value: clock.__setitem__(0, clock[0] + value))
        self.assertEqual(attempts, [3, 3, 3])
        self.assertEqual(clock[0], 4)

        clock[0] = 0
        with self.assertRaises(health.HealthDeadline):
            health.wait_ready(lambda timeout: False, seconds=5,
                              now=lambda: clock[0], sleep=lambda value: clock.__setitem__(0, clock[0] + value))
        self.assertEqual(clock[0], 5)


if __name__ == '__main__':
    unittest.main()
