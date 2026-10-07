#!/usr/bin/env python3
"""Real CLI, Unix IPC and HTTP inside an empty network-isolated container.

Both authorities are synthetic fixtures, not native cgroup or model evidence.
"""
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading

from test_model_chat import AdmissionFixture, chat


def main():
    if os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise SystemExit('requires a disposable root test container')
    root = Path('/var/lib/luma-os')
    root.mkdir(mode=0o700)
    (root/'model-auth').mkdir(mode=0o700)
    (root/'model-selection.json').write_text(json.dumps({'schema_version':2, 'id':'fixture-model'}))
    token = 'a'*64
    (root/'model-auth/api-key').write_text(token)
    broker_root = Path('/run/luma-broker')
    broker_root.mkdir(mode=0o700)
    binary = '/usr/libexec/luma-os/luma-platform'
    preloader = Path(os.environ['TMPDIR'])/'resource-history-cmdline-fixture.so'
    assert preloader.is_file()
    environment = dict(os.environ, LD_PRELOAD=str(preloader))
    fixture = [None]
    payload = [None]
    errors = []
    stop = threading.Event()
    peer_pids = []

    def exact(peer, length):
        data = b''
        while len(data) < length:
            block = peer.recv(length-len(data))
            if not block:
                raise ValueError('fixture request truncated')
            data += block
        return data

    def broker(listener):
        while not stop.is_set():
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                continue
            try:
                with peer:
                    peer.settimeout(3)
                    pid, uid, _ = struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    assert uid == 0 and pid > 0
                    peer_pids.append(pid)
                    size = struct.unpack('!I',exact(peer,4))[0]
                    assert 0 < size <= 16384
                    request = chat.strict_json(exact(peer,size))
                    assert set(request) == {'schema_version','request_id','caller','deadline','action','payload'}
                    assert request['schema_version'] == 2 and request['caller'] == uid
                    assert request['action'] == 'resource-inference'
                    assert chat.decimal(request['deadline']) > chat.boot_ms()
                    try:
                        status = fixture[0].exchange(request['payload'])
                        response = {'schema_version':2,'request_id':request['request_id'],'caller':uid,'result':'ok','status':status}
                    except TimeoutError:
                        response = {'schema_version':2,'request_id':request['request_id'],'caller':uid,'result':'denied','status':{}}
                    if fixture[0].fail_at == 'legacy-wire':
                        response['schema_version'] = 1
                    if fixture[0].fail_at == 'drop-finish-reply' and request['payload']['operation'] == 'finish':
                        # Complete at the fixture authority, then lose the real
                        # socket acknowledgement before any client publication.
                        continue
                    encoded = json.dumps(response).encode()
                    peer.sendall(struct.pack('!I',len(encoded))+encoded)
            except Exception as error:
                errors.append(error)
                stop.set()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):
            self.connection.settimeout(3)
            length = int(self.headers.get('Content-Length','-1'))
            if not 0 < length <= 128*1024:
                self.send_error(400)
                return
            body = chat.strict_json(self.rfile.read(length))
            assert self.headers.get('Authorization') == 'Bearer '+token
            fixture[0].order.append(self.path)
            fixture[0].posts.append((self.path,body))
            if self.path == '/completion':
                assert body['prompt'] == [1,2,3,4,5,6,7,8]
                assert body['n_predict'] == 16 and body['cache_prompt'] is False
                raw = payload[0]
            else:
                raw = json.dumps(fixture[0].responses[self.path]).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    good = AdmissionFixture().responses['/completion']
    fixtures = [('valid',json.dumps(good).encode(),True,None)]
    for label, field, value in (('wrong-model','model','different-model'),
                                ('over-budget','tokens_predicted',17),
                                ('truncated','truncated',True),
                                ('cached-reuse','timings',{'cache_n':1,'prompt_n':8,'predicted_n':1})):
        changed = copy.deepcopy(good)
        changed[field] = value
        fixtures.append((label,json.dumps(changed).encode(),False,None))
    fixtures.extend([
        ('duplicate-model',json.dumps(good).replace('"model":','"model":"other", "model":',1).encode(),False,None),
        ('malformed',b'{invalid-private-fixture',False,None),
        ('denied-admission',json.dumps(good).encode(),False,'admit'),
        ('substituted-input-binding',json.dumps(good).encode(),False,'input-digest'),
        ('legacy-wire-reply',json.dumps(good).encode(),False,'legacy-wire'),
        ('lost-completion-ack',json.dumps(good).encode(),False,'drop-finish-reply')])
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener, \
            http.server.HTTPServer(('127.0.0.1',8081),Handler) as server:
        listener.bind(str(broker_root/'control.sock'))
        listener.listen(8)
        listener.settimeout(.2)
        ipc_thread = threading.Thread(target=broker,args=(listener,))
        http_thread = threading.Thread(target=server.serve_forever)
        ipc_thread.start()
        http_thread.start()
        try:
            invalid_selections = [
                {'schema_version':1, 'id':'fixture-model'},
                {'schema_version':True, 'id':'fixture-model'},
                {'schema_version':2, 'id':'fixture-model', 'transport':'openai-http'},
                {'schema_version':2, 'id':'fixture/model'},
                {'schema_version':2, 'id':'x'*65},
            ]
            for selection in invalid_selections:
                fixture[0] = AdmissionFixture()
                (root/'model-selection.json').write_text(json.dumps(selection))
                result = subprocess.run([binary,'model-chat','--timeout-seconds','3','--max-tokens','16'],
                    env=environment,input=b'Short greeting.',capture_output=True,timeout=8)
                assert result.returncode != 0 and result.stdout == b''
                assert b'local inference response failed validation' in result.stderr
                assert b'Traceback' not in result.stderr and token.encode() not in result.stderr
                assert fixture[0].order == [] and not errors, (selection, fixture[0].order, errors)
                print('CLI_SELECTION_REFUSAL_CASE_PASSED',flush=True)
            (root/'model-selection.json').write_text(json.dumps({'schema_version':2, 'id':'fixture-model'}))
            for label, raw, allowed, fail_at in fixtures:
                fixture[0] = AdmissionFixture()
                fixture[0].fail_at = fail_at
                if fail_at == 'input-digest':
                    fixture[0].corrupt = ('begin','input_digest','0'*64)
                payload[0] = raw
                result = subprocess.run([binary,'model-chat','--timeout-seconds','3','--max-tokens','16'],
                    env=environment,input=b'Short greeting.',capture_output=True,timeout=8)
                assert not errors, errors
                if allowed:
                    assert result.returncode == 0, (label,result.stderr)
                    record = chat.strict_json(result.stdout)
                    assert record['model'] == 'fixture-model' and record['text'] == 'Hello'
                    assert record['usage'] == {'prompt_tokens':8,'completion_tokens':1,'total_tokens':9}
                    assert record['effects_executed'] is False and record['certification_closing'] is False
                    assert record['resource_worker'] == fixture[0].worker
                    assert record['resource_input_digest'] == hashlib.sha256(
                        b'luma-native-operator-prompt-v1\x00Short greeting.').hexdigest()
                    assert fixture[0].order == ['inspect','begin','/apply-template','/tokenize','admit','/completion','finish']
                else:
                    assert result.returncode != 0 and result.stdout == b'', label
                    assert b'local inference response failed validation' in result.stderr, (label,result.stderr)
                    assert b'Traceback' not in result.stderr and b'invalid-private-fixture' not in result.stderr, label
                    if fail_at == 'legacy-wire':
                        assert fixture[0].order == ['inspect']
                        assert fixture[0].posts == []
                    else:
                        assert fixture[0].order[-1] == 'cancel', (label,fixture[0].order)
                    if fail_at == 'input-digest':
                        assert '/apply-template' not in fixture[0].order
                    if fail_at == 'admit':
                        assert '/completion' not in fixture[0].order
                assert token.encode() not in result.stdout+result.stderr, label
                print('CLI_UNIX_HTTP_CASE_PASSED '+label,flush=True)
        finally:
            stop.set()
            server.shutdown()
            http_thread.join(5)
            ipc_thread.join(5)
            assert not http_thread.is_alive() and not ipc_thread.is_alive()
    assert len(set(peer_pids)) == len(fixtures)
    print('MODEL_REPLY_CLI_UNIX_HTTP_PASSED cases='+str(len(fixtures)+len(invalid_selections))+
          ' compiled_native_cli=true test_only_cmdline_preload=true synthetic_authorities=true real_model_tested=false',flush=True)


if __name__ == '__main__':
    main()
