"""Local inference credentials must never follow a server-directed redirect."""
import importlib.util
import contextlib
import copy
import http.server
import io
import json
from pathlib import Path
import signal
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
                    encoded.replace(b'"total_tokens": 9', b'"total_tokens": NaN')):
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
        stdin = mock.Mock(buffer=io.BytesIO(b'Reply with a greeting.'))
        opener = mock.Mock()
        # A context-manager transport fixture, not an actual model response.
        transport = mock.MagicMock()
        opener.open.return_value = transport
        transport.__enter__.return_value.read.return_value = json.dumps(runtime_reply()).encode()
        with mock.patch.object(chat.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(chat.sys, 'stdin', stdin), \
                mock.patch.object(chat.Path, 'read_text', side_effect=['{"id":"fixture-model"}', 'public-fixture-key']), \
                mock.patch.object(chat, 'local_opener', return_value=opener):
            result = chat.inference(chat.arguments(['--max-tokens','16']))
        request = opener.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, 'http://127.0.0.1:8081/v1/chat/completions')
        self.assertEqual(request.get_header('Authorization'), 'Bearer public-fixture-key')
        self.assertEqual(body['chat_template_kwargs'], {'enable_thinking':False})
        self.assertEqual(body['reasoning_effort'], 'none')
        self.assertEqual(body['max_tokens'], 16)
        self.assertFalse(body['stream'])
        self.assertFalse(result['effects_executed'])
        self.assertNotIn('public-fixture-key', json.dumps(result))

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


if __name__=='__main__':unittest.main()
