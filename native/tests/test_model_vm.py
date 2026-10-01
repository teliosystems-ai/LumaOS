"""Inference fixture oracles; these tests do not execute a model."""
import json
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
from model_vm_test import MODEL, arguments, failure_diagnostics, infer, inference_budget, inference_result


class ModelCommandLineTests(unittest.TestCase):
    def test_default_and_explicit_stage_deadline(self):
        base = ['--image', '/work/artifacts/example.img', '--work', '/work/vm-test']
        self.assertEqual(arguments(base).timeout, 5400)
        self.assertFalse(arguments(base).bounded_model_chat)
        self.assertTrue(arguments(base+['--bounded-model-chat']).bounded_model_chat)
        for seconds in (60, 5400, 21600):
            args = arguments(base+['--timeout', str(seconds), '--require-clean-shutdown'])
            self.assertEqual(args.timeout, seconds)
            self.assertTrue(args.require_clean_shutdown)

    def test_invalid_deadline_is_rejected_before_opening_image_or_work(self):
        for value in ('0', '-1', '59', '21601', '1.5', 'forever'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                arguments(['--image', '/absent', '--work', '/absent', '--timeout', value])
            self.assertEqual(error.exception.code, 2)


class ModelResultTests(unittest.TestCase):
    def setUp(self):
        self.result = {'model': MODEL, 'text': 'Hello',
                       'usage': {'completion_tokens': 2},
                       'effects_executed': False, 'certification_closing': False}

    def encode(self):
        return json.dumps(self.result).encode()+b'\r\n'

    def test_fresh_result_with_real_positive_token_count(self):
        self.assertEqual(inference_result(b'console command\r\n'+self.encode(), MODEL), self.result)

    def test_emulation_has_explicit_budget_without_changing_legacy_image_cli(self):
        self.assertEqual(inference_budget('tcg'), (1800, 16))
        self.assertEqual(inference_budget('kvm'), (180, 128))
        vm = mock.Mock(acceleration='tcg')
        vm.run.return_value = self.encode()
        infer(vm)
        self.assertNotIn('--timeout-seconds', vm.run.call_args.args[0])
        self.result.update(timeout_seconds=1800, max_tokens=16, elapsed_seconds=200)
        vm.run.return_value = self.encode()
        infer(vm, bounded=True)
        self.assertIn('--timeout-seconds 1800 --max-tokens 16', vm.run.call_args.args[0])
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 1860)

    def test_bounded_fixture_rejects_missing_or_inconsistent_observations(self):
        vm = mock.Mock(acceleration='tcg')
        self.result.update(timeout_seconds=1800, max_tokens=16, elapsed_seconds=200)
        for field, value in (('timeout_seconds', 180), ('max_tokens', 128),
                             ('elapsed_seconds', None), ('elapsed_seconds', float('nan')),
                             ('elapsed_seconds', True), ('elapsed_seconds', 1801),
                             ('elapsed_seconds', -1), ('usage', {'completion_tokens': 17})):
            original = self.result[field]
            self.result[field] = value
            vm.run.return_value = self.encode()
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                infer(vm, bounded=True)
            self.result[field] = original

    def test_missing_or_duplicate_current_result_never_reuses_old_success(self):
        inference_result(self.encode(), MODEL)
        for output in (b'', b'healthy\r\n', self.encode()*2):
            with self.assertRaises(RuntimeError):
                inference_result(output, MODEL)

    def test_wrong_model_empty_text_and_authority_claims_refused(self):
        for field, value in (('model', 'other-model'), ('text', ''), ('text', None),
                             ('effects_executed', True), ('effects_executed', 0),
                             ('certification_closing', True)):
            original = self.result[field]
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                self.result[field] = value
                inference_result(self.encode(), MODEL)
            self.result[field] = original

    def test_usage_requires_integer_completion_count(self):
        for value in (None, {}, {'completion_tokens': 0}, {'completion_tokens': -1},
                      {'completion_tokens': True}, {'completion_tokens': 1.5}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.result['usage'] = value
                inference_result(self.encode(), MODEL)

    def test_failure_diagnostics_are_bounded_and_do_not_request_credentials(self):
        vm = mock.Mock()
        self.assertTrue(failure_diagnostics(vm))
        command = vm.run.call_args.args[0]
        self.assertIn('memory.events', command)
        self.assertIn('journalctl', command)
        self.assertNotIn('Environment', command)
        self.assertNotIn('api-key', command)
        self.assertEqual(vm.run.call_args.kwargs['timeout'], 30)
        vm.run.side_effect = TimeoutError('guest unreachable')
        self.assertFalse(failure_diagnostics(vm))


if __name__ == '__main__':
    unittest.main()
