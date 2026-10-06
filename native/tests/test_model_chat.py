"""Local inference credentials must never follow a server-directed redirect."""
import importlib.util
import contextlib
import copy
import hashlib
import http.server
import io
import json
from pathlib import Path
import signal
import socket
import struct
import threading
import time
import unittest
from unittest import mock
import urllib.request

SCRIPT=Path(__file__).resolve().parents[1]/'image/overlay/usr/libexec/luma-os/model-chat.py'
spec=importlib.util.spec_from_file_location('model_chat',SCRIPT)
chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(chat)


def runtime_reply():
    return {'model':'fixture-model', 'object':'chat.completion',
            'choices':[{'index':0, 'finish_reason':'stop',
                        'message':{'role':'assistant', 'content':'Hello'}}],
            'usage':{'prompt_tokens':8, 'completion_tokens':1, 'total_tokens':9}}


class ModelCompletionTests(unittest.TestCase):
    def parse(self, result):
        return chat.completion(json.dumps(result).encode(), 'fixture-model', 16)

    def test_exact_model_completion_and_only_bounded_usage_are_returned(self):
        result = runtime_reply()
        result['usage']['untrusted_extra'] = 'private-fixture'
        for reason in ('stop', 'length'):
            result['choices'][0]['finish_reason'] = reason
            text, usage = self.parse(result)
            self.assertEqual(text, 'Hello')
            self.assertEqual(usage, {'prompt_tokens':8, 'completion_tokens':1, 'total_tokens':9})
            self.assertNotIn('private-fixture', json.dumps(usage))

    def test_wrong_identity_missing_or_multiple_choices_are_refused(self):
        baseline = runtime_reply()
        for key, value in (('model', 'different-model'), ('model', None),
                           ('object', 'chat.completion.chunk'), ('choices', []),
                           ('choices', baseline['choices'] * 2), ('choices', [None])):
            result = copy.deepcopy(baseline)
            result[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)
        for result in ([], None, {}, 'not-an-object'):
            with self.subTest(result=result), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)

    def test_only_finished_assistant_text_without_tool_dispatch_is_accepted(self):
        for key, value in (('index', True), ('index', 1), ('finish_reason', None),
                           ('finish_reason', 'tool_calls'), ('message', None)):
            result = runtime_reply()
            result['choices'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)
        for key, value in (('role', 'system'), ('content', ''), ('content', '  '),
                           ('content', []), ('tool_calls', [{'type':'function'}]),
                           ('function_call', {}), ('refusal', 'refused')):
            result = runtime_reply()
            result['choices'][0]['message'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)

    def test_missing_non_integer_negative_over_budget_or_inconsistent_usage_is_refused(self):
        for usage in (None, {}, {'prompt_tokens':8, 'completion_tokens':1}):
            result = runtime_reply()
            result['usage'] = usage
            with self.subTest(usage=usage), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)
        for key, value in (('prompt_tokens', 0), ('prompt_tokens', -1), ('prompt_tokens', True),
                           ('completion_tokens', 0), ('completion_tokens', 17),
                           ('completion_tokens', 1.0), ('total_tokens', 10), ('total_tokens', '9')):
            result = runtime_reply()
            result['usage'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(chat.InferenceReplyError):
                self.parse(result)

    def test_malformed_duplicate_nonfinite_or_excessively_nested_json_is_refused(self):
        encoded = json.dumps(runtime_reply()).encode()
        for raw in (b'\xff', b'{', b'[' * 1500 + b']' * 1500,
                    encoded.replace(b'"model":', b'"model":"other", "model":', 1),
                    encoded.replace(b'"completion_tokens":', b'"completion_tokens":99, "completion_tokens":', 1),
                    encoded.replace(b'"total_tokens": 9', b'"total_tokens": NaN'),
                    encoded.decode().encode('utf-16'),
                    encoded.replace(b'Hello',b'\\ud800')):
            with self.subTest(raw=raw[:60]), self.assertRaises(chat.InferenceReplyError):
                chat.completion(raw, 'fixture-model', 16)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_invalid_reply_returns_no_success_or_untrusted_error_details(self):
        with mock.patch.object(chat, 'arguments', return_value=chat.arguments([])), \
                mock.patch.object(chat, 'inference', side_effect=chat.InferenceReplyError('private-fixture')), \
                contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as error:
            chat.main()
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn('private-fixture', str(error.exception))
        self.assertIn('response failed validation', str(error.exception))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


class ModelChatTransportTests(unittest.TestCase):
    def test_every_redirect_target_is_refused(self):
        req=urllib.request.Request('http://127.0.0.1:8081/v1/chat/completions',
            headers={'Authorization':'Bearer public-test-fixture'},data=b'{}')
        for target in ('https://example.invalid', 'http://127.0.0.1:9999', '/other'):
            for code in (301,302,303,307,308):
                with self.subTest(target=target,code=code), self.assertRaises(ValueError):
                    chat.NoRedirect().redirect_request(req,None,code,'redirect',{},target)

    def test_opener_does_not_install_default_redirect_handler(self):
        handlers=chat.local_opener().handlers
        redirects=[h for h in handlers if isinstance(h,urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirects),1)
        self.assertIsInstance(redirects[0],chat.NoRedirect)
        for handler in handlers:
            if isinstance(handler,urllib.request.ProxyHandler):
                self.assertEqual(handler.proxies,{})


class ModelChatBudgetTests(unittest.TestCase):
    def test_smoke_request_disables_reasoning_and_keeps_fixed_local_authority(self):
        fixture = AdmissionFixture()
        result = fixture.run()
        self.assertEqual(fixture.order, ['inspect', 'begin', '/apply-template', '/tokenize', 'admit', '/completion', 'finish'])
        template = fixture.posts[0][1]
        self.assertEqual(template['chat_template_kwargs'], {'enable_thinking':False})
        self.assertTrue(template['messages'][0]['content'].endswith(' /no_think'))
        self.assertEqual(fixture.posts[1][1], {'content':'rendered-fixture', 'add_special':True, 'parse_special':True, 'with_pieces':False})
        completion = fixture.posts[2][1]
        self.assertEqual(completion['prompt'], [1,2,3,4,5,6,7,8])
        self.assertEqual(completion['n_predict'],16)
        self.assertFalse(completion['cache_prompt'])
        self.assertFalse(completion['stream'])
        self.assertFalse(result['effects_executed'])
        self.assertFalse(result['certification_closing'])
        self.assertNotIn('a' * 64, json.dumps(result))

    def test_defaults_and_finite_operator_limits(self):
        args = chat.arguments([])
        self.assertEqual((args.timeout_seconds, args.max_tokens), (180, 128))
        for timeout, tokens in ((1, 1), (1800, 128), (1800, 16)):
            args = chat.arguments(['--timeout-seconds', str(timeout), '--max-tokens', str(tokens)])
            self.assertEqual((args.timeout_seconds, args.max_tokens), (timeout, tokens))

    def test_invalid_options_fail_before_reading_prompt_or_credentials(self):
        for option, values in (('--timeout-seconds', ('0', '-1', '1801', 'nan', '1.5')),
                               ('--max-tokens', ('0', '-1', '129', 'nan', '1.5')),
                               ('--endpoint', ('https://example.invalid',))):
            for value in values:
                with self.subTest(option=option, value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    chat.arguments([option, value])
                self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_deadline_interrupts_blocking_operation_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            with chat.whole_request_deadline(.05):
                time.sleep(2)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_normal_and_error_paths_disarm_timer(self):
        with chat.whole_request_deadline(1):
            pass
        with self.assertRaises(ValueError):
            with chat.whole_request_deadline(1):
                raise ValueError('fixture')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_nested_deadline_is_refused_without_replacing_outer(self):
        with chat.whole_request_deadline(1):
            before = signal.getitimer(signal.ITIMER_REAL)[0]
            with self.assertRaises(RuntimeError):
                with chat.whole_request_deadline(10):
                    self.fail('nested timer accepted')
            self.assertLessEqual(signal.getitimer(signal.ITIMER_REAL)[0], before)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_trickling_http_body_cannot_restart_whole_request_budget(self):
        stop = threading.Event()
        class Trickle(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '100')
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b'x')
                        self.wfile.flush()
                        if stop.wait(.02):
                            break
                except (BrokenPipeError, ConnectionResetError):
                    pass
        with http.server.HTTPServer(('127.0.0.1', 0), Trickle) as server:
            # Bound accept even if client setup fails before connecting. Begin
            # the body deadline only after real response headers arrive, so
            # CPU contention cannot turn this into a connect-timeout test.
            server.timeout = 2
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                with chat.local_opener().open(f'http://127.0.0.1:{server.server_port}', timeout=2) as response:
                    start = time.monotonic()
                    with self.assertRaises(TimeoutError):
                        with chat.whole_request_deadline(.2):
                            response.read(100)
                    self.assertLess(time.monotonic() - start, 1)
            finally:
                stop.set()
                thread.join(3)
                self.assertFalse(thread.is_alive())

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'Linux CLI deadline')
    def test_transport_failure_has_no_success_object_or_exception_details(self):
        with mock.patch.object(chat, 'arguments', return_value=chat.arguments([])), \
                mock.patch.object(chat, 'inference', side_effect=TimeoutError('private fixture')), \
                contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as error:
            chat.main()
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn('private fixture', str(error.exception))
        self.assertIn('manual operation remains available', str(error.exception))


class AdmissionFixture:
    """Protocol fixtures only: no model execution or physical drainage claim."""
    def __init__(self):
        self.worker = {'lease_id':'1'*32, 'generation':'1', 'manager_epoch':'2'*32}
        self.order = []
        self.posts = []
        self.messages = []
        self.fail_at = None
        self.responses = {'/apply-template': {'prompt':'rendered-fixture'},
            '/tokenize': {'tokens':[1,2,3,4,5,6,7,8]},
            '/completion': {'model':'fixture-model','content':'Hello','tokens_predicted':1,
                'tokens_evaluated':8,'tokens_cached':8,'stop':True,'stop_type':'eos','truncated':False,
                'timings': {'cache_n':0,'prompt_n':8,'predicted_n':1}}}
        self.corrupt = None
        self.expected = None
        self.admitted = None

    def exchange(self, payload):
        operation = payload['operation']
        self.order.append(operation)
        self.messages.append(copy.deepcopy(payload))
        if operation == 'inspect':
            return {'kind':'worker', 'worker':self.worker, 'profile':'fixture-model',
                    'context_tokens':'2048','max_output_tokens':'128','slots':'1'}
        if operation == 'begin':
            self.expected = {key:payload[key] for key in ('nonce','worker','profile','max_output_tokens','request_deadline','input_digest')}
            self.expected['context_tokens'] = '2048'
        if operation == self.fail_at:
            raise TimeoutError('private fixture')
        if operation == 'admit':
            self.admitted = payload
        phase = {'begin':'preparing','admit':'admitted','finish':'completed','cancel':'draining'}[operation]
        receipt = {'kind':'permit', **self.expected, 'phase':phase,
                   'prompt_tokens':None if self.admitted is None else self.admitted['prompt_tokens'],
                   'token_digest':None if self.admitted is None else self.admitted['token_digest'],
                   'output_tokens':payload.get('output_tokens'), 'result_digest':payload.get('result_digest'),
                   'slot_released':phase == 'completed', 'worker_resources_released':False}
        if self.corrupt is not None and operation == self.corrupt[0]:
            receipt[self.corrupt[1]] = self.corrupt[2]
        return receipt

    def post(self, opener, path, payload, token, timeout):
        self.order.append(path)
        self.posts.append((path, payload))
        if path == self.fail_at:
            raise TimeoutError('private fixture')
        return self.responses[path]

    def run(self, prompt=b'Reply with a greeting.'):
        def opened(path, mode):
            if str(path).endswith('model-selection.json'):
                return io.BytesIO(b'{"id":"fixture-model"}')
            return io.BytesIO(b'a' * 64)
        with mock.patch.object(chat.os,'geteuid',return_value=0,create=True), \
                mock.patch.object(chat.sys,'stdin',mock.Mock(buffer=io.BytesIO(prompt))), \
                mock.patch.object(chat.Path,'open',autospec=True,side_effect=opened), \
                mock.patch.object(chat,'boot_ms',return_value=1000), \
                mock.patch.object(chat,'broker_exchange',side_effect=self.exchange), \
                mock.patch.object(chat,'runtime_post',side_effect=self.post), \
                mock.patch.object(chat,'local_opener',return_value=mock.Mock()):
            return chat.inference(chat.arguments(['--max-tokens','16']))


class NativeAdmissionTests(unittest.TestCase):
    def test_exact_original_input_bytes_are_bound_before_template_and_checked_through_completion(self):
        digests=set()
        for prompt in (b'hello',b' hello',b'hello\n','héllo'.encode(),b'hello /no_think'):
            fixture=AdmissionFixture()
            result=fixture.run(prompt)
            expected=hashlib.sha256(b'luma-native-operator-prompt-v1\x00'+prompt).hexdigest()
            self.assertEqual(fixture.messages[1]['input_digest'],expected)
            self.assertEqual(fixture.expected['input_digest'],expected)
            self.assertEqual(result['resource_input_digest'],expected)
            self.assertLess(fixture.order.index('begin'),fixture.order.index('/apply-template'))
            self.assertEqual(fixture.posts[0][1]['messages'][0]['content'],prompt.decode()+' /no_think')
            self.assertNotIn('messages',fixture.messages[1])
            self.assertNotIn('content',fixture.messages[1])
            digests.add(expected)
        self.assertEqual(len(digests),5)

    def test_each_uncertain_step_cancels_same_generation_without_publishing_result(self):
        for step in ('begin','/apply-template','/tokenize','admit','/completion','finish'):
            with self.subTest(step=step):
                fixture = AdmissionFixture()
                fixture.fail_at = step
                with self.assertRaises(TimeoutError):
                    fixture.run()
                self.assertEqual(fixture.order[-1], 'cancel')
                begin = fixture.messages[1]
                self.assertEqual(fixture.messages[-1], {'operation':'cancel','nonce':begin['nonce'],'worker':begin['worker']})

    def test_oversized_invalid_or_retemplated_prompt_never_reaches_completion(self):
        for value in ([], [True], [-1], [2147483648], ['1'], [1]*2033, [1]*2049):
            with self.subTest(value=str(value)[:40]):
                fixture = AdmissionFixture()
                fixture.responses['/tokenize'] = {'tokens':value}
                with self.assertRaises(chat.InferenceReplyError):
                    fixture.run()
                self.assertNotIn('/completion', fixture.order)
                self.assertEqual(fixture.order[-1], 'cancel')
        for value in ({'prompt':''}, {'prompt':1}, {'prompt':'x','extra':1}):
            fixture = AdmissionFixture()
            fixture.responses['/apply-template'] = value
            with self.assertRaises(chat.InferenceReplyError):
                fixture.run()
            self.assertNotIn('/tokenize', fixture.order)

    def test_invalid_actual_output_counts_cached_reuse_and_truncation_are_fenced(self):
        for key, value in (('model','other'), ('stop',False), ('stop_type','unknown'), ('truncated',True),
                           ('tokens_evaluated',9), ('tokens_predicted',0), ('tokens_predicted',17),
                           ('tokens_predicted',True), ('tokens_cached',25), ('tokens_cached',-1),
                           ('content',''), ('timings',{'cache_n':1,'prompt_n':8,'predicted_n':1}),
                           ('timings',{'cache_n':0,'prompt_n':7,'predicted_n':1}),
                           ('timings',{'cache_n':0,'prompt_n':8,'predicted_n':2})):
            with self.subTest(key=key,value=value):
                fixture = AdmissionFixture()
                fixture.responses['/completion'][key] = value
                with self.assertRaises(chat.InferenceReplyError):
                    fixture.run()
                self.assertNotIn('finish', fixture.order)
                self.assertEqual(fixture.order[-1], 'cancel')

    def test_substituted_or_premature_release_receipts_are_denied(self):
        for operation, key, value in (('begin','worker',{'lease_id':'3'*32,'generation':'2','manager_epoch':'2'*32}),
                                    ('begin','phase','admitted'), ('begin','slot_released',True),
                                    ('begin','input_digest','0'*64), ('begin','input_digest',None),
                                    ('admit','input_digest','0'*64), ('finish','input_digest',None),
                                    ('admit','prompt_tokens','9'), ('admit','token_digest','b'*64),
                                    ('finish','output_tokens','2'), ('finish','worker_resources_released',True)):
            with self.subTest(operation=operation,key=key):
                fixture = AdmissionFixture()
                fixture.corrupt = (operation,key,value)
                with self.assertRaises(chat.InferenceReplyError):
                    fixture.run()
                self.assertEqual(fixture.order[-1], 'cancel')

    def test_invalid_utf8_is_denied_before_any_broker_or_runtime_work(self):
        fixture = AdmissionFixture()
        with self.assertRaises(chat.InferenceReplyError):
            fixture.run(b'\xff')
        self.assertEqual(fixture.order, [])

    def test_lossless_counts_and_worker_schema_reject_ambiguous_values(self):
        self.assertEqual(chat.decimal(str((1<<64)-1)), (1<<64)-1)
        for value in (True, 1, '01', '-1', '+1', '１', '', str(1<<64)):
            with self.subTest(value=value), self.assertRaises(chat.InferenceReplyError):
                chat.decimal(value)
        baseline = AdmissionFixture().worker
        for field,value in (('generation','0'), ('generation',1), ('manager_epoch','G'*32), ('extra',1)):
            worker = dict(baseline)
            worker[field] = value
            with self.assertRaises(chat.InferenceReplyError):
                chat.worker_token(worker)

    def test_runtime_posts_are_bounded_fixed_loopback_and_authenticated(self):
        opener = mock.Mock()
        transport = mock.MagicMock()
        opener.open.return_value = transport
        response = transport.__enter__.return_value
        response.status = 200
        response.read.return_value = b'{"tokens":[1]}'
        result = chat.runtime_post(opener,'/tokenize',{'content':'fixture'},'a'*64,1)
        self.assertEqual(result, {'tokens':[1]})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url,'http://127.0.0.1:8081/tokenize')
        self.assertEqual(request.get_header('Authorization'),'Bearer '+'a'*64)
        response.read.assert_called_once_with(128*1024+1)
        for path in ('/v1/chat/completions','https://example.invalid','/slots/0?action=save'):
            with self.assertRaises(chat.InferenceReplyError):
                chat.runtime_post(opener,path,{},'a'*64,1)
        response.read.return_value = b'x'*(128*1024+1)
        with self.assertRaises(chat.InferenceReplyError):
            chat.runtime_post(opener,'/tokenize',{},'a'*64,1)


@unittest.skipUnless(hasattr(socket,'SO_PEERCRED'), 'Linux Unix peer credentials')
class NativeBrokerExchangeTests(unittest.TestCase):
    def exchange(self, mutate=None, raw=None, header=None, uid=None):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        def exact(peer, size):
            result = b''
            while len(result)<size:
                chunk = peer.recv(size-len(result))
                if not chunk:
                    raise ValueError('fixture truncated')
                result += chunk
            return result
        errors = []
        def broker():
            try:
                with server:
                    server.settimeout(2)
                    request = json.loads(exact(server,struct.unpack('!I',exact(server,4))[0]))
                    self.assertEqual(request['action'],'resource-inference')
                    self.assertEqual(request['caller'],0)
                    self.assertIsInstance(request['deadline'],str)
                    response = {'schema_version':2,'request_id':request['request_id'],'caller':0,'result':'ok','status':{'kind':'fixture'}}
                    if mutate:
                        mutate(response)
                    encoded = raw if raw is not None else json.dumps(response).encode()
                    server.sendall(header if header is not None else struct.pack('!I',len(encoded))+encoded)
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as error:
                errors.append(error)
        wrapped = mock.Mock(wraps=client)
        wrapped.__enter__ = mock.Mock(return_value=wrapped)
        wrapped.__exit__ = mock.Mock(side_effect=lambda *args:client.close())
        wrapped.connect = mock.Mock()
        if uid is not None:
            wrapped.getsockopt = mock.Mock(return_value=struct.pack('3i',1,uid,0))
        thread = threading.Thread(target=broker)
        thread.start()
        try:
            with mock.patch.object(chat.socket,'socket',return_value=wrapped):
                return chat.broker_exchange({'operation':'inspect'})
        finally:
            client.close()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            if errors:
                raise errors[0]

    def test_real_unix_frame_and_root_peer_credentials_are_verified(self):
        self.assertEqual(self.exchange(), {'kind':'fixture'})

    def test_non_root_broker_peer_is_refused_before_sending_any_request(self):
        peer = mock.MagicMock()
        peer.__enter__.return_value = peer
        peer.getsockopt.return_value = struct.pack('3i',1,990,990)
        with mock.patch.object(chat.socket,'socket',return_value=peer), self.assertRaises(chat.InferenceReplyError):
            chat.broker_exchange({'operation':'inspect'})
        peer.sendall.assert_not_called()

    def test_trickling_frames_cannot_extend_boot_time_exchange_deadline(self):
        elapsed = [0]
        frame = struct.pack('!I',100) + b'x'*100
        delivered = [0]
        def recv(length):
            elapsed[0] += 700
            offset = delivered[0]
            delivered[0] += 1
            return frame[offset:offset+1]
        peer = mock.MagicMock()
        peer.__enter__.return_value = peer
        peer.getsockopt.return_value = struct.pack('3i',1,0,0)
        peer.recv.side_effect = recv
        with mock.patch.object(chat.socket,'socket',return_value=peer), \
                mock.patch.object(chat,'boot_ms',side_effect=lambda:elapsed[0]), self.assertRaises(TimeoutError):
            chat.broker_exchange({'operation':'inspect'})
        self.assertLessEqual(delivered[0],5)

    def test_closed_reply_identity_and_result_are_required(self):
        for field,value in (('caller',True), ('schema_version',True), ('schema_version',1), ('request_id','other'),
                            ('result','denied'), ('status',[]), ('extra',1)):
            with self.subTest(field=field), self.assertRaises(chat.InferenceReplyError):
                self.exchange(mutate=lambda response:response.update({field:value}))

    def test_oversized_empty_truncated_duplicate_and_nonfinite_frames_are_refused(self):
        for header in (struct.pack('!I',0),struct.pack('!I',16385),struct.pack('!I',10)+b'{}',b'\x00'):
            with self.subTest(header=header), self.assertRaises(chat.InferenceReplyError):
                self.exchange(header=header)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(chat.InferenceReplyError):
                self.exchange(raw=raw)


if __name__=='__main__':unittest.main()
