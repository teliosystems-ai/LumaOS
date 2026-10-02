#!/usr/bin/env python3
"""Real CLI/HTTP validation in an empty disposable, network-isolated container.

Replies are synthetic fixtures, NOT real-model or image acceptance evidence.
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

from test_model_chat import runtime_reply


def main():
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('requires a disposable root test container')
    root = Path('/var/lib/luma-os')
    # Refuse an existing runtime/configuration rather than modifying it.
    root.mkdir(mode=0o700)
    (root / 'model-auth').mkdir(mode=0o700)
    (root / 'model-selection.json').write_text(json.dumps({'schema_version':1, 'id':'fixture-model'}))
    token = 'PUBLIC-CLI-HTTP-TEST-FIXTURE'
    (root / 'model-auth/api-key').write_text(token)
    script = Path(__file__).resolve().parents[1] / 'image/overlay/usr/libexec/luma-os/model-chat.py'
    requests = []
    payload = [b'']

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(3)
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 < length < 16384:
                self.send_error(400)
                return
            body = json.loads(self.rfile.read(length))
            requests.append((self.path, self.headers.get('Authorization'), body))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload[0])))
            self.end_headers()
            self.wfile.write(payload[0])

    good = runtime_reply()
    wrong = runtime_reply()
    wrong['model'] = 'different-model'
    over = runtime_reply()
    over['usage'].update(completion_tokens=17, total_tokens=25)
    tool = runtime_reply()
    tool['choices'][0]['message']['tool_calls'] = [{'type':'function'}]
    fixtures = [('valid', json.dumps(good).encode(), True),
                ('wrong-model', json.dumps(wrong).encode(), False),
                ('over-budget', json.dumps(over).encode(), False),
                ('tool-call', json.dumps(tool).encode(), False),
                ('duplicate-model', json.dumps(good).replace('"model":', '"model":"other", "model":', 1).encode(), False),
                ('malformed', b'{invalid-private-fixture', False)]
    with http.server.HTTPServer(('127.0.0.1', 8081), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for label, raw, allowed in fixtures:
                payload[0] = raw
                result = subprocess.run([sys.executable, str(script), '--timeout-seconds', '3', '--max-tokens', '16'],
                                        input=b'Short greeting.', capture_output=True, timeout=8)
                if allowed:
                    assert result.returncode == 0, (label, result.stderr)
                    record = json.loads(result.stdout)
                    assert record['model'] == 'fixture-model' and record['text'] == 'Hello'
                    assert record['usage'] == good['usage']
                    assert record['effects_executed'] is False and record['certification_closing'] is False
                else:
                    assert result.returncode != 0 and result.stdout == b'', label
                    assert b'local inference response failed validation' in result.stderr, label
                    assert b'Traceback' not in result.stderr and b'invalid-private-fixture' not in result.stderr, label
                assert token.encode() not in result.stdout + result.stderr, label
                print('CLI_HTTP_CASE_PASSED ' + label, flush=True)
        finally:
            server.shutdown()
            thread.join(5)
            assert not thread.is_alive()
    assert len(requests) == len(fixtures)
    for path, authorization, body in requests:
        assert path == '/v1/chat/completions' and authorization == 'Bearer ' + token
        assert body['model'] == 'fixture-model' and body['max_tokens'] == 16
        assert body['stream'] is False
    print('MODEL_REPLY_CLI_HTTP_PASSED synthetic_runtime=true real_model_tested=false', flush=True)


if __name__ == '__main__':
    main()
